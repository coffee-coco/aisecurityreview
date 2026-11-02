"""Code uploads: safe archive extraction and a whole-codebase inventory.

Uploads are stored per review under UPLOAD_DIR/<review>/code/<document id>/ so several uploads
(e.g. a frontend zip, a backend zip and a pasted snippet) are reviewed together as one system.
"""
from __future__ import annotations

import io
import json
import re
import shutil
import stat
import tarfile
import zipfile
from collections import Counter
from pathlib import Path, PurePosixPath

from ..config import MAX_CODE_FILES, MAX_CODE_UNPACKED_MB

SKIP_DIRS = {
    "node_modules", ".git", ".hg", ".svn", ".venv", "venv", "env", "__pycache__", "dist", "build", ".next", ".nuxt",
    ".terraform", "target", "vendor", "bower_components", ".gradle", ".mvn", "coverage", ".pytest_cache",
    ".mypy_cache", "site-packages", ".idea", ".vscode", ".tox", ".cache", "out", "bin", "obj", "Pods", ".dart_tool",
    "__MACOSX", ".serverless", ".aws-sam", "cdk.out",
}
BINARY_EXT = {
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".bmp", ".tiff", ".pdf", ".zip", ".gz", ".tgz", ".tar", ".7z",
    ".rar", ".jar", ".war", ".ear", ".class", ".so", ".dll", ".dylib", ".exe", ".bin", ".o", ".a", ".pyc", ".pyo",
    ".woff", ".woff2", ".ttf", ".otf", ".eot", ".mp3", ".mp4", ".mov", ".avi", ".wav", ".psd", ".sketch", ".fig",
    ".db", ".sqlite", ".sqlite3", ".parquet", ".avro", ".pkl", ".h5", ".onnx", ".pt", ".safetensors", ".lock",
    ".map", ".min.js", ".DS_Store",
}
MAX_FILE_BYTES = 2_000_000  # single source files larger than this are skipped

LANG_BY_EXT = {
    ".py": "Python", ".js": "JavaScript", ".mjs": "JavaScript", ".cjs": "JavaScript", ".jsx": "JavaScript",
    ".ts": "TypeScript", ".tsx": "TypeScript", ".java": "Java", ".kt": "Kotlin", ".kts": "Kotlin", ".go": "Go",
    ".rb": "Ruby", ".php": "PHP", ".cs": "C#", ".fs": "F#", ".vb": "VB.NET", ".rs": "Rust", ".c": "C", ".h": "C",
    ".cpp": "C++", ".cc": "C++", ".hpp": "C++", ".swift": "Swift", ".m": "Objective-C", ".scala": "Scala",
    ".dart": "Dart", ".lua": "Lua", ".pl": "Perl", ".r": "R", ".sql": "SQL", ".sh": "Shell", ".bash": "Shell",
    ".zsh": "Shell", ".ps1": "PowerShell", ".psm1": "PowerShell", ".bat": "Batch", ".cmd": "Batch",
    ".tf": "Terraform", ".tfvars": "Terraform", ".hcl": "HCL", ".bicep": "Bicep", ".yaml": "YAML", ".yml": "YAML",
    ".json": "JSON", ".toml": "TOML", ".ini": "INI", ".cfg": "INI", ".conf": "Config", ".properties": "Properties",
    ".xml": "XML", ".gradle": "Gradle", ".html": "HTML", ".htm": "HTML", ".vue": "Vue", ".svelte": "Svelte",
    ".css": "CSS", ".scss": "SCSS", ".md": "Markdown", ".env": "Env", ".graphql": "GraphQL", ".gql": "GraphQL",
    ".proto": "Protobuf", ".ipynb": "Notebook", ".groovy": "Groovy", ".ex": "Elixir", ".exs": "Elixir",
}
NAME_LANG = {"dockerfile": "Dockerfile", "jenkinsfile": "Groovy", "makefile": "Make", "procfile": "Config",
             ".env": "Env", "gemfile": "Ruby", "vagrantfile": "Ruby"}

SNIPPET_EXT = {"python": ".py", "javascript": ".js", "typescript": ".ts", "java": ".java", "go": ".go",
               "csharp": ".cs", "ruby": ".rb", "php": ".php", "terraform": ".tf", "yaml": ".yaml", "json": ".json",
               "shell": ".sh", "sql": ".sql", "dockerfile": "Dockerfile", "kotlin": ".kt", "rust": ".rs",
               "html": ".html", "bicep": ".bicep", "text": ".txt"}

ARCHIVE_EXT = (".zip", ".tar", ".tar.gz", ".tgz")


class UnpackError(ValueError):
    pass


def is_archive(filename: str) -> bool:
    return filename.lower().endswith(ARCHIVE_EXT)


def _safe_parts(name: str) -> list[str] | None:
    name = name.replace("\\", "/")
    if name.startswith("/") or re.match(r"^[A-Za-z]:", name):
        return None
    parts = [p for p in PurePosixPath(name).parts if p not in ("", ".")]
    if not parts or any(p == ".." for p in parts):
        return None  # zip-slip
    if any(p in SKIP_DIRS for p in parts[:-1]):
        return []  # skipped directory (not an error)
    return parts


def _skip_file(name: str, size: int) -> bool:
    low = name.lower()
    return size > MAX_FILE_BYTES or any(low.endswith(e.lower()) for e in BINARY_EXT)


def _write(dest: Path, parts: list[str], src, budget: dict) -> None:
    target = dest.joinpath(*parts)
    if not str(target.resolve()).startswith(str(dest.resolve())):
        raise UnpackError("archive entry escapes the extraction directory")
    target.parent.mkdir(parents=True, exist_ok=True)
    with open(target, "wb") as out:
        while chunk := src.read(65536):
            budget["bytes"] += len(chunk)
            if budget["bytes"] > MAX_CODE_UNPACKED_MB * 1024 * 1024:
                raise UnpackError(f"archive expands beyond {MAX_CODE_UNPACKED_MB} MB")
            out.write(chunk)
    budget["files"] += 1
    if budget["files"] > MAX_CODE_FILES:
        raise UnpackError(f"archive has more than {MAX_CODE_FILES} source files")


def extract_archive(filename: str, data: bytes, dest: Path) -> dict:
    """Extract an archive safely: no path traversal, no symlinks, size/count limits, skips vendored dirs."""
    dest.mkdir(parents=True, exist_ok=True)
    budget = {"bytes": 0, "files": 0, "skipped": 0, "unsafe": 0}
    try:
        if filename.lower().endswith(".zip"):
            with zipfile.ZipFile(io.BytesIO(data)) as z:
                for info in z.infolist():
                    if info.is_dir():
                        continue
                    mode = info.external_attr >> 16
                    if stat.S_ISLNK(mode):
                        budget["unsafe"] += 1
                        continue
                    parts = _safe_parts(info.filename)
                    if parts is None:
                        budget["unsafe"] += 1
                        continue
                    if not parts or _skip_file(info.filename, info.file_size):
                        budget["skipped"] += 1
                        continue
                    with z.open(info) as src:
                        _write(dest, parts, src, budget)
        else:
            with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as t:
                for m in t.getmembers():
                    if not m.isfile():
                        if m.issym() or m.islnk():
                            budget["unsafe"] += 1
                        continue
                    parts = _safe_parts(m.name)
                    if parts is None:
                        budget["unsafe"] += 1
                        continue
                    if not parts or _skip_file(m.name, m.size):
                        budget["skipped"] += 1
                        continue
                    src = t.extractfile(m)
                    if src:
                        _write(dest, parts, src, budget)
    except (zipfile.BadZipFile, tarfile.TarError) as e:
        shutil.rmtree(dest, ignore_errors=True)
        raise UnpackError(f"not a valid archive: {e}") from e
    except UnpackError:
        shutil.rmtree(dest, ignore_errors=True)
        raise
    _flatten_single_root(dest)
    return {"files": budget["files"], "bytes": budget["bytes"], "skipped": budget["skipped"],
            "unsafe_entries": budget["unsafe"]}


def _flatten_single_root(dest: Path) -> None:
    """repo.zip often contains one top folder (repo-main/) - lift its contents for nicer paths."""
    entries = [p for p in dest.iterdir()]
    if len(entries) == 1 and entries[0].is_dir():
        inner = entries[0]
        for child in inner.iterdir():
            shutil.move(str(child), dest / child.name)
        inner.rmdir()


def sanitize_tree(dest: Path) -> dict:
    """Apply the archive rules to a directory that was filled by another tool (e.g. git clone).

    Removes symlinks, vendored/build directories and binary or oversized files, then enforces the same file-count
    and unpacked-size limits as ``extract_archive``.
    """
    stats = {"files": 0, "bytes": 0, "skipped": 0, "unsafe_entries": 0}
    for p in sorted(dest.rglob("*"), key=lambda x: len(x.parts), reverse=True):  # children before parents
        if p.is_symlink():
            p.unlink(missing_ok=True)
            stats["unsafe_entries"] += 1
        elif p.is_dir() and p.name in SKIP_DIRS:
            shutil.rmtree(p, ignore_errors=True)
    for p in sorted(dest.rglob("*")):
        if not p.is_file():
            continue
        size = p.stat().st_size
        if _skip_file(p.name, size):
            p.unlink(missing_ok=True)
            stats["skipped"] += 1
            continue
        stats["files"] += 1
        stats["bytes"] += size
        if stats["files"] > MAX_CODE_FILES:
            raise UnpackError(f"repository has more than {MAX_CODE_FILES} source files")
        if stats["bytes"] > MAX_CODE_UNPACKED_MB * 1024 * 1024:
            raise UnpackError(f"repository expands beyond {MAX_CODE_UNPACKED_MB} MB")
    return stats


def save_file(filename: str, data: bytes, dest: Path) -> dict:
    parts = _safe_parts(filename) or [Path(filename).name or "file.txt"]
    dest.mkdir(parents=True, exist_ok=True)
    target = dest.joinpath(*parts[-3:])
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(data)
    return {"files": 1, "bytes": len(data), "skipped": 0, "unsafe_entries": 0}


def snippet_filename(name: str, language: str) -> str:
    ext = SNIPPET_EXT.get((language or "text").lower(), ".txt")
    base = re.sub(r"[^A-Za-z0-9_.-]+", "_", (name or "snippet").strip())[:60] or "snippet"
    if ext == "Dockerfile":
        return "Dockerfile"
    return base if base.lower().endswith(ext) else base + ext


# --------------------------------------------------------------------------- inventory
def language_of(path: str) -> str:
    p = PurePosixPath(path)
    name = p.name.lower()
    if name in NAME_LANG:
        return NAME_LANG[name]
    if name.startswith("dockerfile"):
        return "Dockerfile"
    if name.startswith(".env"):
        return "Env"
    return LANG_BY_EXT.get(p.suffix.lower(), "")


def read_text(path: Path) -> str | None:
    try:
        data = path.read_bytes()
    except OSError:
        return None
    if b"\x00" in data[:8192]:
        return None
    return data.decode("utf-8", "replace")


def iter_sources(roots: list[tuple[str, Path]]):
    """Yield (display_path, absolute Path) for every reviewable file across all code uploads."""
    multi = len(roots) > 1
    for label, root in roots:
        if not root.exists():
            continue
        for p in sorted(root.rglob("*")):
            if not p.is_file() or p.is_symlink():
                continue
            rel = p.relative_to(root).as_posix()
            if any(part in SKIP_DIRS for part in rel.split("/")[:-1]):
                continue
            if _skip_file(rel, p.stat().st_size):
                continue
            yield (f"{label}/{rel}" if multi else rel), p


MANIFESTS = {
    "package.json": "npm", "requirements.txt": "pip", "pyproject.toml": "python", "pipfile": "pipenv",
    "setup.py": "python", "pom.xml": "maven", "build.gradle": "gradle", "build.gradle.kts": "gradle",
    "go.mod": "go", "cargo.toml": "cargo", "gemfile": "bundler", "composer.json": "composer",
    "pubspec.yaml": "dart", "mix.exs": "elixir",
}
IAC_PATTERNS = [
    (r"\.tf$", "Terraform"), (r"(^|/)dockerfile[^/]*$", "Dockerfile"), (r"docker-compose[^/]*\.ya?ml$", "Docker Compose"),
    (r"(^|/)\.github/workflows/[^/]+\.ya?ml$", "GitHub Actions"), (r"(^|/)\.gitlab-ci\.ya?ml$", "GitLab CI"),
    (r"(^|/)bitbucket-pipelines\.ya?ml$", "Bitbucket Pipelines"), (r"azure-pipelines[^/]*\.ya?ml$", "Azure Pipelines"),
    (r"(^|/)jenkinsfile$", "Jenkins"), (r"(^|/)chart\.ya?ml$", "Helm"), (r"\.bicep$", "Bicep"),
    (r"(^|/)serverless\.ya?ml$", "Serverless"), (r"(^|/)template\.ya?ml$", "CloudFormation/SAM"),
    (r"(^|/)cdk\.json$", "AWS CDK"), (r"\.(cfn|cloudformation)\.(ya?ml|json)$", "CloudFormation"),
]
FRAMEWORKS = {
    # web / api
    "express": "Express", "fastify": "Fastify", "@nestjs/core": "NestJS", "next": "Next.js", "react": "React",
    "@angular/core": "Angular", "vue": "Vue", "svelte": "Svelte", "koa": "Koa", "hapi": "hapi",
    "django": "Django", "flask": "Flask", "fastapi": "FastAPI", "starlette": "Starlette", "tornado": "Tornado",
    "spring-boot": "Spring Boot", "rails": "Rails", "laravel/framework": "Laravel", "gin-gonic/gin": "Gin",
    "labstack/echo": "Echo", "gofiber/fiber": "Fiber", "aspnetcore": "ASP.NET Core", "graphql": "GraphQL",
    # data / auth
    "sqlalchemy": "SQLAlchemy", "prisma": "Prisma", "sequelize": "Sequelize", "mongoose": "Mongoose",
    "typeorm": "TypeORM", "psycopg2": "PostgreSQL driver", "pymongo": "MongoDB driver", "redis": "Redis client",
    "jsonwebtoken": "JWT (jsonwebtoken)", "pyjwt": "PyJWT", "passport": "Passport", "next-auth": "NextAuth",
    "helmet": "Helmet", "cors": "CORS middleware", "bcrypt": "bcrypt", "argon2": "Argon2",
    # cloud
    "boto3": "AWS SDK (boto3)", "aws-sdk": "AWS SDK (JS v2)", "@aws-sdk/": "AWS SDK (JS v3)",
    "azure-": "Azure SDK", "@azure/": "Azure SDK", "google-cloud-": "Google Cloud SDK", "@google-cloud/": "Google Cloud SDK",
    # AI
    "openai": "OpenAI SDK", "anthropic": "Anthropic SDK", "@anthropic-ai/sdk": "Anthropic SDK",
    "google-generativeai": "Gemini SDK", "google-genai": "Gemini SDK", "@google/generative-ai": "Gemini SDK",
    "langchain": "LangChain", "llama-index": "LlamaIndex", "llama_index": "LlamaIndex", "crewai": "CrewAI",
    "autogen": "AutoGen", "semantic-kernel": "Semantic Kernel", "transformers": "Hugging Face Transformers",
    "chromadb": "Chroma", "pinecone": "Pinecone", "weaviate": "Weaviate", "faiss": "FAISS", "mcp": "Model Context Protocol",
    "@modelcontextprotocol/sdk": "Model Context Protocol", "ollama": "Ollama", "litellm": "LiteLLM",
}
AI_FRAMEWORKS = {"OpenAI SDK", "Anthropic SDK", "Gemini SDK", "LangChain", "LlamaIndex", "CrewAI", "AutoGen",
                 "Semantic Kernel", "Hugging Face Transformers", "Model Context Protocol", "Ollama", "LiteLLM",
                 "Chroma", "Pinecone", "Weaviate", "FAISS"}

ROUTE_PATTERNS = [
    re.compile(r"""@(?:app|router|api|bp|blueprint)\.(get|post|put|patch|delete|route|api_route)\(\s*['"]([^'"]+)"""),
    re.compile(r"""\b(?:app|router|server)\.(get|post|put|patch|delete|all|use)\(\s*['"`](/[^'"`]*)"""),
    re.compile(r"""@(Get|Post|Put|Patch|Delete|Request)Mapping\(\s*(?:value\s*=\s*)?['"]([^'"]+)"""),
    re.compile(r"""\.(GET|POST|PUT|PATCH|DELETE|HandleFunc|Handle)\(\s*["'`](/[^"'`]*)"""),
    re.compile(r"""\bpath\(\s*['"]([^'"]*)['"]\s*,\s*([\w.]+)"""),
]


def _deps_from_manifest(name: str, text: str) -> list[str]:
    name = name.lower()
    deps: list[str] = []
    try:
        if name == "package.json":
            j = json.loads(text)
            for k in ("dependencies", "devDependencies", "peerDependencies"):
                deps += list((j.get(k) or {}).keys())
        elif name == "requirements.txt":
            deps = [re.split(r"[<>=!~\[; ]", ln.strip(), 1)[0] for ln in text.splitlines()
                    if ln.strip() and not ln.strip().startswith(("#", "-"))]
        elif name in ("pyproject.toml", "pipfile", "setup.py"):
            deps = re.findall(r"""["']([A-Za-z0-9_.\-]+)\s*(?:[<>=~!\[]|["'])""", text)
        elif name == "go.mod":
            deps = re.findall(r"^\s*([\w.\-]+/[\w.\-/]+)\s+v", text, re.M)
        elif name in ("pom.xml",):
            deps = re.findall(r"<artifactId>([^<]+)</artifactId>", text)
        elif name.startswith("build.gradle"):
            deps = re.findall(r"""['"]([\w.\-]+:[\w.\-]+)(?::[\w.\-]+)?['"]""", text)
        elif name in ("cargo.toml", "gemfile", "composer.json", "pubspec.yaml"):
            deps = re.findall(r"""^\s*['"]?([\w\-/]+)['"]?\s*[=:]""", text, re.M)
    except (json.JSONDecodeError, ValueError):
        pass
    return [d.strip().lower() for d in deps if d and len(d) < 100]


def build_inventory(roots: list[tuple[str, Path]]) -> dict:
    files: list[dict] = []
    langs: Counter = Counter()
    manifests, iac, deps, routes = [], Counter(), set(), []
    for path, p in iter_sources(roots):
        text = read_text(p)
        if text is None:
            continue
        lines = text.count("\n") + 1
        lang = language_of(path)
        files.append({"path": path, "lang": lang, "lines": lines, "bytes": len(text.encode())})
        if lang:
            langs[lang] += lines
        base = PurePosixPath(path).name.lower()
        if base in MANIFESTS:
            manifests.append({"path": path, "type": MANIFESTS[base]})
            deps.update(_deps_from_manifest(base, text))
        if base.endswith(".csproj"):
            manifests.append({"path": path, "type": "nuget"})
            deps.update(d.lower() for d in re.findall(r'PackageReference Include="([^"]+)"', text))
        low = path.lower()
        for pat, kind in IAC_PATTERNS:
            if re.search(pat, low):
                iac[kind] += 1
        if lang in ("YAML", "JSON") and re.search(r"^\s*apiVersion:\s*\S+\s*$", text, re.M) and "kind:" in text:
            iac["Kubernetes"] += 1
        if lang in ("YAML", "JSON") and "AWSTemplateFormatVersion" in text:
            iac["CloudFormation"] += 1
        if len(routes) < 300 and lang not in ("Markdown", "JSON", "YAML"):
            for rx in ROUTE_PATTERNS:
                for m in rx.finditer(text):
                    line = text.count("\n", 0, m.start()) + 1
                    method, route = (m.group(1), m.group(2)) if rx.pattern.find("path\\(") < 0 else ("PATH", m.group(1))
                    routes.append({"method": method.upper(), "route": route, "file": path, "line": line})
    frameworks = sorted({label for dep in deps for key, label in FRAMEWORKS.items()
                         if dep == key or (key.endswith(("-", "/")) and dep.startswith(key))})
    total_lines = sum(f["lines"] for f in files)
    return {
        "files": len(files), "lines": total_lines, "file_list": files,
        "languages": [{"name": k, "lines": v, "pct": round(100 * v / max(1, total_lines), 1)}
                      for k, v in langs.most_common(12)],
        "manifests": manifests, "dependencies": sorted(deps)[:400], "dependency_count": len(deps),
        "frameworks": frameworks, "ai_frameworks": [f for f in frameworks if f in AI_FRAMEWORKS],
        "iac": [{"type": k, "files": v} for k, v in iac.most_common()],
        "routes": routes[:300],
    }
