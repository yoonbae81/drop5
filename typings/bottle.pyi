from collections.abc import Callable, Mapping
from typing import BinaryIO, NoReturn, TypeVar

_Handler = TypeVar("_Handler", bound=Callable[..., object])


class DictProperty(Mapping[str, str]):
    scheme: str
    netloc: str
    def get(self, key: str, default: str | None = ...) -> str | None: ...
    def getall(self, key: str) -> list[str]: ...


class Request:
    path: str
    remote_addr: str | None
    query: DictProperty
    headers: DictProperty
    forms: DictProperty
    files: FileUploadMap
    json: dict[str, str] | None
    environ: dict[str, str]
    urlparts: UrlParts
    def get_cookie(self, name: str, default: str | None = ...) -> str | None: ...
    def get_header(self, name: str, default: str | None = ...) -> str | None: ...


class Response:
    status: int
    content_type: str
    def set_header(self, name: str, value: str) -> None: ...
    def set_cookie(self, name: str, value: str, **kwargs: object) -> None: ...
    def delete_cookie(self, name: str, **kwargs: object) -> None: ...


class BaseRequest:
    MEMFILE_MAX: int


class UrlParts:
    scheme: str
    netloc: str


class FileUpload:
    raw_filename: str | None
    file: BinaryIO
    def save(self, destination: str, overwrite: bool = ...) -> None: ...


class FileUploadMap(Mapping[str, FileUpload]):
    def get(self, key: str, default: FileUpload | None = ...) -> FileUpload | None: ...
    def getall(self, key: str) -> list[FileUpload]: ...


class Bottle:
    def route(self, *rules: str | None, **options: object) -> Callable[[_Handler], _Handler]: ...
    def hook(self, name: str) -> Callable[[_Handler], _Handler]: ...
    def error(self, code: int) -> Callable[[_Handler], _Handler]: ...
    def get(self, *rules: str | None, **options: object) -> Callable[[_Handler], _Handler]: ...
    def post(self, *rules: str | None, **options: object) -> Callable[[_Handler], _Handler]: ...
    def install(self, plugin: object) -> None: ...
    def run(self, host: str, port: int, debug: bool, reloader: bool) -> None: ...
    routes: list[Route]


class Route:
    rule: str


request: Request
response: Response
TEMPLATE_PATH: list[str]

def static_file(filename: str, root: str, mimetype: str | bool | None = ..., download: bool = ...) -> object: ...
def redirect(url: str, code: int | None = ...) -> NoReturn: ...
def abort(code: int, text: str | None = ...) -> NoReturn: ...
def template(name: str, **kwargs: object) -> str: ...
