맞습니다. `Drop5`는 기존 기능을 그대로 유지하면서 **Python/Gunicorn/systemd/local filesystem을 제거하고 Cloudflare-native 구조로 재설계**하는 것이 목표가 되어야 합니다. 아래 정도를 그대로 `AGENTS.md`나 포팅 작업 지침으로 넣어도 됩니다. 현재 Cloudflare 사양도 반영했습니다.

# Drop5 Cloudflare Native Porting Guide

## 1. 목표

현재 Drop5의 사용자 경험과 핵심 보안 정책을 유지하면서 기존 Linux 서버 기반 아키텍처를 Cloudflare-native 구조로 전환한다.

기존:

```text
Browser
  ↓
Cloudflare / Reverse Proxy
  ↓
Gunicorn
  ↓
Python Application
  ├─ Memory / Session
  ├─ Local files/
  ├─ Audit log
  └─ CrowdSec
```

목표:

```text
Browser
  ↓
Cloudflare
  ↓
Worker
  ├─ Static Assets
  ├─ HTTP API
  ├─ validation
  └─ routing
       │
       ├── Durable Object
       │    ├─ session state
       │    ├─ client approval
       │    ├─ WebSocket
       │    └─ expiration alarm
       │
       └── R2
            └─ temporary files
```

가능한 한 별도 서버, VM, Container, Python runtime을 사용하지 않는다.

---

# 2. 가장 중요한 설계 원칙

Cloudflare에 기존 Python 서버를 그대로 재현하려 하지 않는다.

다음 대응 관계를 기준으로 재설계한다.

```text
Python HTTP Server   → Worker
Gunicorn             → 제거
systemd              → 제거
Local filesystem     → R2
Python session state → Durable Objects
AJAX polling         → WebSocket
TTL cleanup loop     → Durable Object Alarm
CrowdSec             → Cloudflare WAF / Rate Limiting
HTML/CSS/JS          → Worker Static Assets
```

Worker는 가능한 한 stateless하게 유지한다.

세션에 종속된 상태는 모두 Durable Object가 소유한다.

---

# 3. Application 단위

GitHub repository는 기존처럼 하나를 유지한다.

```text
github.com/yoonbae81/drop5
```

Cloudflare에서도 논리적으로 `drop5` 하나의 application으로 취급한다.

별도의 repository를 다음과 같이 만들지 않는다.

```text
drop5-worker
drop5-r2
drop5-durable-object
drop5-websocket
```

모두 하나의 repository에서 관리한다.

권장 구조:

```text
drop5/
├─ src/
│  ├─ index.ts
│  │
│  ├─ durable/
│  │  └─ session.ts
│  │
│  ├─ routes/
│  │  ├─ session.ts
│  │  ├─ upload.ts
│  │  ├─ download.ts
│  │  └─ websocket.ts
│  │
│  ├─ lib/
│  │  ├─ filename.ts
│  │  ├─ validation.ts
│  │  ├─ security.ts
│  │  └─ responses.ts
│  │
│  └─ types/
│
├─ public/
│  ├─ index.html
│  ├─ js/
│  ├─ css/
│  └─ i18n/
│
├─ test/
│  ├─ unit/
│  └─ integration/
│
├─ wrangler.jsonc
├─ package.json
├─ tsconfig.json
└─ README.md
```

---

# 4. URL 및 API 호환성

기존 URL 구조를 가능한 한 유지한다.

특히 다음 경로의 의미를 변경하지 않는다.

```text
GET  /<session-code>

POST /<session-code>/join
POST /<session-code>/heartbeat

GET  /<session-code>/files
POST /<session-code>/upload

GET  /<session-code>/download/<filename>
DELETE 또는 기존 삭제 endpoint
```

iOS Shortcut에서 사용하는 다음 API 역시 유지한다.

```text
POST /<session-code>/upload
```

JSON 업로드:

```json
{
  "content": "text"
}
```

Form upload 역시 기존 호환성을 유지한다.

Cloudflare 전환을 이유로 외부 API를 불필요하게 변경하지 않는다.

---

# 5. 세션 = Durable Object

Drop5의 핵심 모델은 다음과 같이 정의한다.

> 하나의 session code = 하나의 Durable Object

예:

```text
Session code
D5-N6J9-KQ...

        ↓

Durable Object
Session:D5-N6J9-KQ...
```

Durable Object ID는 session code에서 deterministic하게 생성한다.

예:

```ts
env.SESSIONS.idFromName(sessionCode)
```

한 세션의 상태는 다른 Durable Object에 나누지 않는다.

Durable Object가 다음 정보를 소유한다.

```text
session
├─ createdAt
├─ expiresAt
├─ hostClientId
│
├─ clients
│   ├─ clientId
│   ├─ approved
│   ├─ joinedAt
│   └─ lastSeen
│
└─ files
    ├─ fileId
    ├─ originalName
    ├─ objectKey
    ├─ size
    ├─ uploadedAt
    └─ expiresAt
```

중요한 상태는 JavaScript memory에만 저장하지 않는다.

Durable Object는 hibernation 또는 restart 후 constructor가 다시 실행될 수 있으므로 필요한 상태는 SQLite-backed Durable Object storage에 저장한다. :chatgpt-content-reference{index="0"}

---

# 6. Durable Object는 SQLite-backed storage 사용

새 구현에서는 SQLite-backed Durable Objects를 기본으로 사용한다.

이 방식은 Workers Free에서도 사용 가능하다.

현재 Free plan에서는 account당 Durable Object storage 5GB, Durable Object 하나당 최대 10GB이며 Drop5의 session metadata 용도로는 충분하다. :chatgpt-content-reference{index="1"}

단:

> 실제 공유 파일은 Durable Object에 저장하지 않는다.

파일은 반드시 R2에 저장한다.

Durable Object에는 metadata만 저장한다.

---

# 7. 파일 저장 = R2

기존:

```text
files/
```

를 완전히 제거한다.

모든 업로드 파일은 R2에 저장한다.

권장 object key:

```text
sessions/<session-id>/<file-id>
```

또는:

```text
sessions/<session-id>/<file-id>/<normalized-name>
```

원본 파일명을 object key 식별자로 직접 사용하지 않는다.

파일명은 metadata로 별도 관리한다.

이를 통해:

- 동일 파일명 충돌 방지
- path traversal 방지
- Unicode/NFC 문제 분리
- 내부 object URL 추측 방지

를 달성한다.

---

# 8. R2 bucket은 private 유지

R2 bucket 자체를 public website처럼 공개하지 않는다.

사용자는 항상:

```text
https://drop5.net/<session>/download/<file>
```

을 통해 다운로드한다.

흐름:

```text
Browser
  ↓
Worker
  ↓
Session DO
  ↓
권한 확인
  ↓
R2.get()
  ↓
stream response
```

따라서 R2 object URL이 사용자에게 영구적으로 노출되지 않도록 한다.

---

# 9. 현재 30MB 파일은 Worker를 통한 업로드를 우선

현재 Drop5 제한은:

```text
MAX_FILE_SIZE = 30MB
MAX_STORAGE_SIZE = 100MB / session
MAX_FILES = 30
```

이므로 초기 Cloudflare 버전에서는 구조를 단순하게 유지한다.

```text
Browser
 ↓
Worker
 ↓
validation
 ↓
R2
```

방식을 사용한다.

Cloudflare Free/Pro의 HTTP request body limit는 현재 100MB이므로 파일당 30MB 제한은 여유 있게 들어온다. :chatgpt-content-reference{index="2"}

단, Worker memory에 파일 전체를 `ArrayBuffer` 등으로 적재하는 구현은 피한다.

가능한 경우 request body를 streaming 방식으로 R2에 전달한다.

---

# 10. 향후 대용량 파일 지원 시 direct upload

향후 파일 크기를 예를 들어:

```text
30MB
→ 500MB
→ 1GB
```

등으로 확대할 경우 upload architecture를 다음처럼 변경할 수 있도록 설계한다.

```text
Browser
 ↓
Worker
 ↓
upload authorization
 ↓
temporary presigned URL

Browser
 ─────────→ R2
```

R2는 presigned PUT URL을 지원하며 URL 유효기간을 제한할 수 있다. :chatgpt-content-reference{index="3"}

더 큰 파일은 multipart upload를 사용한다. R2는 single PUT 5GiB, multipart는 최대 약 5TiB를 지원한다. :chatgpt-content-reference{index="4"}

하지만 현재 30MB 요구사항에서는 처음부터 presigned/multipart 구조를 도입하지 않는다.

YAGNI 원칙을 적용한다.

---

# 11. 5분 TTL 구현

Drop5의 핵심 특성:

> 파일은 업로드 후 5분 뒤 실제로 삭제된다.

이를 R2 Lifecycle Rule에 맡기지 않는다.

R2 Lifecycle Rule은 exact 5-minute expiration mechanism이 아니다.

주 삭제 메커니즘은 Durable Object Alarm으로 구현한다.

파일 저장 시:

```text
uploadedAt = now
expiresAt = now + 300 seconds
```

를 저장한다.

Durable Object가 alarm을 등록한다.

Cloudflare Durable Object Alarm은 scheduled time에 Object를 깨울 수 있으며 실패 시 자동 retry되는 at-least-once 실행 방식이다. :chatgpt-content-reference{index="5"}

---

# 12. Alarm은 파일마다 하나씩 만들 수 없다는 점에 주의

하나의 Durable Object는 동시에 alarm 하나만 설정할 수 있다. :chatgpt-content-reference{index="6"}

따라서 다음처럼 구현하면 안 된다.

```text
file A → alarm A
file B → alarm B
file C → alarm C
```

대신:

```text
files

A expires 12:05
B expires 12:07
C expires 12:09
```

이면 alarm은:

```text
12:05
```

하나만 등록한다.

12:05 alarm 실행:

```text
1. expiresAt <= now인 파일 탐색
2. 해당 R2 objects 삭제
3. metadata 삭제
4. 다음 expiration 확인
5. 가장 빠른 12:07에 새 alarm 설정
```

하는 방식으로 구현한다.

이 규칙은 반드시 테스트한다.

---

# 13. R2 Lifecycle은 secondary safety net

Application bug나 Alarm failure로 파일이 남는 상황에 대비해 R2 bucket에는 장기 safety cleanup rule을 추가한다.

예:

```text
정상:
Durable Object Alarm
→ 약 5분 후 삭제

비정상 상황:
R2 Lifecycle
→ 1일 후 강제 삭제
```

Lifecycle은 정확한 서비스 TTL 구현 용도가 아니라 orphan object 제거용 safety net으로만 사용한다.

---

# 14. AJAX polling → WebSocket

현재 파일 목록, 참여자, 승인 상태 확인을 위해 AJAX polling을 사용한다.

Cloudflare version에서는 가능하면 다음 구조로 전환한다.

```text
Browser
   ↕
WebSocket
   ↕
Session Durable Object
```

다음 event들을 정의한다.

```text
client-joined
client-approved
client-rejected

file-uploaded
file-deleted
file-expired

session-expired
```

예:

```json
{
  "type": "file-uploaded",
  "file": {
    "id": "...",
    "name": "report.pdf",
    "size": 123456,
    "expiresAt": 1791345900000
  }
}
```

HTTP polling은 기본 실시간 mechanism에서 제거한다.

필요하다면 fallback 용도로만 유지한다.

---

# 15. WebSocket Hibernation API 사용

일반 WebSocket API보다 Durable Objects의 WebSocket Hibernation API를 사용한다.

Cloudflare 역시 Durable Objects WebSocket 서버에서는 Hibernation API 사용을 권장한다. 연결을 유지한 상태로 Durable Object가 memory에서 내려갈 수 있어 idle duration 비용을 줄일 수 있다. :chatgpt-content-reference{index="7"}

따라서:

```text
WebSocket 연결 존재
≠
Durable Object가 5분 동안 계속 active
```

가 되도록 설계한다.

사용자별 필요한 connection metadata는 WebSocket attachment 등을 이용하여 복원 가능하게 한다.

---

# 16. countdown은 서버에서 매초 push하지 않는다

현재 UI에서 5분 countdown을 초 단위로 보여주더라도 다음과 같이 구현하지 않는다.

```text
Server
→ 매초 WebSocket message
→ 모든 client
```

서버는:

```text
expiresAt
```

만 전달한다.

브라우저에서:

```js
remaining = expiresAt - Date.now()
```

으로 countdown을 계산한다.

즉:

```text
Cloudflare
→ expiration timestamp

Browser
→ 초 단위 rendering
```

으로 역할을 분리한다.

---

# 17. Heartbeat도 최소화

WebSocket 연결 자체로 client presence를 상당 부분 알 수 있으므로 기존 `/heartbeat` 호출 빈도를 재검토한다.

기존 API compatibility 때문에 endpoint는 남길 수 있으나 Cloudflare-native UI에서는 불필요한 HTTP polling과 heartbeat를 줄인다.

목표는:

```text
polling 없음
1초 heartbeat 없음
server timer 없음
```

이다.

---

# 18. 승인 모델은 기존 semantics 유지

기존 Drop5의 중요한 정책은 그대로 유지한다.

### Browser participant

새 기기가 session에 join:

```text
New Client
 ↓
Session Durable Object
 ↓
pending
 ↓
Host WebSocket notification
 ↓
Host approval
 ↓
approved
```

승인되기 전에는:

- 파일 목록 노출 금지
- 다운로드 금지
- 기존 사용자 정보 최소화

정책을 유지한다.

---

# 19. Shortcut upload semantics 유지

현재 iOS Shortcut upload는 특별한 의미가 있다.

```text
POST /<session-code>/upload
```

는 session code를 알고 있으면 host approval 없이 upload할 수 있다.

Cloudflare port에서도 이 동작을 임의로 변경하지 않는다.

단:

- session quota
- file count
- file size
- filename validation
- extension restrictions
- rate limiting

은 동일하게 적용한다.

보안 모델 자체를 변경하고 싶은 경우 별도 설계 변경으로 취급한다.

---

# 20. Host 개념과 ownership을 명확하게 관리

첫 browser client가 session을 생성하면 host 역할을 부여한다.

단 Shortcut upload가 존재하므로:

```text
첫 upload request
```

가 반드시 host browser를 의미하지 않는다.

따라서:

```text
session existence
```

와:

```text
host assignment
```

을 분리한다.

Shortcut가 먼저 파일을 올려도 이후 첫 interactive browser가 적절하게 host가 될 수 있도록 기존 동작을 분석한 뒤 동일한 UX를 보존한다.

---

# 21. 파일명 처리 정책 유지

현재 구현의:

- NFC normalization
- path sanitization
- dangerous extension rejection

정책을 유지한다.

특히 macOS → Windows 전송 시 한글 filename normalization 동작을 regression test로 작성한다.

서버 filesystem을 사용하지 않더라도 filename validation은 계속 필요하다.

다음 입력을 별도로 테스트한다.

```text
../file.txt
../../etc/passwd

Á.txt       # decomposed Unicode
Á.txt        # composed Unicode

file.exe
file.sh

...
```

---

# 22. storage quota enforcement는 Durable Object가 담당

세션별:

```text
MAX_FILE_SIZE
MAX_STORAGE_SIZE
MAX_FILES
```

제한을 Worker memory에서 계산하지 않는다.

해당 session의 Durable Object가 authoritative state가 된다.

파일 업로드 전에:

```text
Session DO

currentFiles
currentBytes
newFileSize
```

를 기준으로 admission decision을 내린다.

동시 업로드 race condition에서도 quota가 초과되지 않아야 한다.

이것은 Durable Object를 사용하는 중요한 이유 중 하나다.

---

# 23. 동시 upload race condition을 반드시 테스트

예:

```text
현재 사용량 = 80MB
limit = 100MB

client A → 20MB upload
client B → 20MB upload
```

동시에 들어와도 둘 다 승인되어:

```text
120MB
```

가 되면 안 된다.

Durable Object에서 reservation 개념을 두는 것을 고려한다.

예:

```text
reserve 20MB
 ↓
upload
 ↓
commit
```

실패하면 reservation을 release한다.

---

# 24. R2 object와 metadata 간 consistency

다음 failure들을 고려한다.

### Case A

```text
R2 upload 성공
→ DO metadata update 실패
```

orphan object가 생긴다.

### Case B

```text
DO reservation 성공
→ R2 upload 실패
```

ghost metadata/reservation이 남는다.

### Case C

```text
R2 delete 성공
→ DO update 실패
```

metadata만 남는다.

각 작업은 완전한 distributed transaction이라고 가정하지 않는다.

대신 idempotent operation과 reconciliation을 고려한다.

R2 lifecycle safety cleanup은 orphan cleanup의 최종 방어선이다.

---

# 25. 파일 다운로드는 streaming

다음 방식은 피한다.

```text
R2
 ↓
Worker ArrayBuffer 30MB
 ↓
Response
```

가능하면:

```text
R2
 ↓
ReadableStream
 ↓
Response
```

으로 직접 전달한다.

Worker는 파일 내용을 변환하지 않는다.

적절한:

```text
Content-Type
Content-Length
Content-Disposition
```

을 제공한다.

---

# 26. Static Assets

기존 HTML/CSS/JS는 Worker Static Assets를 사용한다.

가능하면 별도 frontend hosting project를 만들지 않는다.

```text
drop5 Worker
├─ static frontend
└─ API
```

형태로 하나의 deployable unit을 유지한다.

---

# 27. DB는 초기 버전에 도입하지 않는다

D1을 처음부터 추가하지 않는다.

Drop5의 핵심 원칙은:

```text
ephemeral
5-minute expiration
minimal persistence
```

이다.

따라서:

```text
Durable Object
→ session metadata

R2
→ files
```

만으로 구현한다.

장기간 audit log가 정말 필요한 경우에만 D1 또는 별도 logging backend 도입을 검토한다.

---

# 28. Audit 정책 재검토

기존 filesystem audit log를 그대로 Cloudflare에 복제하지 않는다.

먼저 어떤 데이터를 실제로 장기간 보관할 필요가 있는지 분리한다.

예:

```text
operational telemetry
security events
application errors
long-term audit
```

Cloudflare Logs/Analytics로 충분한 정보와 application-level audit를 구분한다.

Drop5의 privacy-first 철학에 맞게 장기간 저장되는 개인정보는 최소화한다.

IP address를 애플리케이션 DB에 불필요하게 보관하지 않는다.

---

# 29. IP detection

Cloudflare 환경에서는 reverse proxy chain을 자체적으로 해석하지 않는다.

필요한 경우 Cloudflare가 제공하는 request 정보를 이용한다.

언어 자동선택은 우선순위를:

```text
1. explicit user selection
2. browser Accept-Language
3. Cloudflare country information
4. default locale
```

정도로 단순화한다.

기존 RIR database 다운로드/update daemon은 제거하는 방향을 우선 검토한다.

---

# 30. CrowdSec 의존성 제거

Cloudflare-native 배포에서는 CrowdSec 자체를 애플리케이션 prerequisite로 두지 않는다.

다음은 Cloudflare 측으로 이동한다.

```text
DDoS protection
basic bot protection
IP blocking
rate limiting
WAF rules
```

Application은 domain-specific validation만 담당한다.

예:

```text
session code validation
file extension policy
file size
file count
session quota
approval state
```

즉:

> infrastructure abuse protection → Cloudflare

> Drop5 business/security policy → application

으로 분리한다.

---

# 31. Session code security

Session code가 사실상 capability token 역할을 하므로 충분한 entropy를 가진 random code를 사용한다.

짧고 사람이 추측 가능한 코드에 의존하지 않는다.

특히 public internet 서비스에서는 brute-force 가능성을 전제로 한다.

Session code 존재 여부가 외부에 쉽게 enumeration되지 않도록 error response도 주의한다.

---

# 32. Rate limit 적용 지점

최소한 다음 endpoint에 abuse protection을 고려한다.

```text
session creation
join
upload
download
```

특히:

```text
POST /<session>/upload
```

은 approval 없이 사용 가능하므로 우선순위가 높다.

단, legitimate multi-file upload를 방해할 정도로 공격적인 rate limit은 적용하지 않는다.

---

# 33. Free plan 우선 설계

초기 목표는 가능한 범위에서 Cloudflare Free plan으로 운영 가능한 구조로 만든다.

다음 서비스를 우선 사용한다.

```text
Workers
R2
Durable Objects
Static Assets
```

Cloudflare-specific paid feature가 필수 아키텍처 dependency가 되지 않게 한다.

필요 시 이후 Paid plan으로 확장한다.

---

# 34. Worker 코드의 책임 제한

Worker `index.ts`에 모든 로직을 넣지 않는다.

Worker는 주로 다음만 담당한다.

```text
URL routing
request parsing
basic validation
static assets
Durable Object routing
R2 streaming
HTTP response
```

Session business logic은 Durable Object로 이동한다.

---

# 35. Durable Object 코드의 책임

`Session` Durable Object는 다음을 책임진다.

```text
session lifecycle
host
clients
approvals
files metadata
quota
reservations
WebSockets
broadcast
expiration
alarms
```

따라서 session에 관한 source of truth는 Session DO 하나여야 한다.

---

# 36. Queue / Workflow는 사용하지 않는다

초기 Drop5 구현에는:

```text
Queues
Workflows
Cron
D1
KV
```

를 넣지 않는다.

현재 요구사항에는 필요하지 않다.

복잡도를 높이기 위한 Cloudflare 기능 사용을 금지한다.

실제 use case가 나타났을 때만 도입한다.

---

# 37. 기존 Python implementation을 specification으로 사용

포팅은 기존 코드를 줄 단위로 번역하는 작업이 아니다.

기존 코드는 다음을 확인하기 위한 executable specification으로 사용한다.

```text
route semantics
session behavior
approval rules
TTL
file validation
filename normalization
errors
i18n
Shortcut compatibility
```

Cloudflare implementation은 동일한 observable behavior를 유지하되 내부 구조는 새로 작성한다.

---

# 38. 테스트 전략

세 단계로 나눈다.

## Unit tests

다음 pure logic을 별도 테스트한다.

```text
session code validation
filename normalization
extension blocking
file size validation
quota calculation
expiration calculation
locale selection
```

Vitest 사용을 기본으로 한다.

---

## Durable Object tests

실제 Workers test runtime에서:

```text
session creation
host assignment
join
approve
reject
file reservation
file metadata
alarm
expiration
WebSocket event
```

를 검증한다.

특히 다음 테스트는 필수다.

```text
A. 두 클라이언트 동시 quota reservation

B. 5분 expiration

C. 서로 다른 시간에 올라온 여러 파일

D. earliest alarm 이후 next alarm 재등록

E. alarm 재실행의 idempotency

F. DO hibernation/restart 후 상태 복구

G. WebSocket disconnect/reconnect
```

---

## Integration tests

실제 HTTP surface를 테스트한다.

예:

```text
create session

→ host connect

→ second device join

→ verify file list inaccessible

→ host approve

→ upload file

→ verify WebSocket event

→ download file

→ delete file
```

R2 + Durable Object + Worker 전체를 포함한다.

---

# 39. Security regression tests

반드시 다음을 테스트한다.

```text
unapproved client file listing
unapproved download
invalid session code

oversized file
session storage overflow
too many files

dangerous extension
path traversal filename
Unicode filename

duplicate filename

simultaneous uploads

expired session access

expired download URL/request
```

---

# 40. 기존 테스트를 버리지 않는다

기존 Python test suite에서 business requirement를 추출한다.

각 기존 test에 대해:

```text
obsolete infrastructure test
vs
still-valid behavior test
```

를 판단한다.

still-valid behavior는 TypeScript/Vitest 버전으로 이전한다.

---

# 41. 포팅 순서

다음 순서를 권장한다.

### Phase 1 — Foundation

```text
Wrangler project
TypeScript
Static Assets
basic routing
```

### Phase 2 — Session

```text
Durable Object
session creation
host/client
approval
```

### Phase 3 — Storage

```text
R2
upload
download
delete
quota
```

### Phase 4 — TTL

```text
Durable Object Alarm
5-minute deletion
next alarm scheduling
R2 safety lifecycle
```

### Phase 5 — Realtime

```text
WebSocket Hibernation
file events
approval events
presence
```

### Phase 6 — Security

```text
rate limiting
WAF
validation
headers
abuse controls
```

### Phase 7 — Migration

```text
production route
DNS
monitoring
old server shutdown
```

---

# 42. 첫 버전에서는 기능 개선보다 parity 우선

포팅 중 다음과 같은 신규 기능을 동시에 추가하지 않는다.

```text
accounts
permanent storage
file history
end-to-end encryption
large-file support
QR workflows
new admin UI
```

먼저:

> Current Drop5 behavior + Cloudflare-native backend

를 완성한다.

그 후 별도 change로 기능을 개선한다.

---

# 43. 완료 조건

Cloudflare 포팅이 완료되었다고 판단하기 위한 조건:

```text
[ ] 별도 Linux application server 불필요
[ ] Python/Gunicorn/systemd 불필요
[ ] local files/ 불필요
[ ] CrowdSec prerequisite 불필요

[ ] Worker에서 HTTP API 제공
[ ] Static Assets에서 frontend 제공
[ ] R2에서 temporary file 저장
[ ] Session별 Durable Object 사용
[ ] WebSocket Hibernation 사용
[ ] 5분 TTL이 Alarm으로 구현됨
[ ] Alarm failure/retry가 idempotent함

[ ] 기존 Browser workflow 유지
[ ] 기존 iOS Shortcut upload 유지
[ ] host approval semantics 유지
[ ] unapproved file listing 차단
[ ] file/session quota 유지
[ ] Unicode filename 동작 유지

[ ] unit tests 통과
[ ] DO tests 통과
[ ] integration tests 통과
[ ] security regression tests 통과
```

---

# 44. 최종 목표 아키텍처

```text
                    drop5.net
                        │
                        ▼
                 Cloudflare Edge
                        │
              ┌─────────┴─────────┐
              │                   │
        Static Assets           Worker
                                  │
                    ┌─────────────┴────────────┐
                    │                          │
             Session Durable Object            R2
                    │                          │
          ┌─────────┼─────────┐                │
          │         │         │                │
       host      client A  client B          files
          │         │         │
          └──── WebSocket ─────┘
                  │
            Hibernation API
                  │
             Session state
                  │
                Alarm
                  │
             after 5 min
                  │
              R2.delete()
```

설계의 핵심은 다음 한 문장으로 정리한다.

> **Worker는 stateless HTTP edge, Durable Object는 한 Drop5 세션의 authoritative coordinator, R2는 5분짜리 ephemeral blob storage로 사용한다.**

이 경계를 흐리지 않는다.

특히 실제 구현하면서 가장 신경 써야 할 부분은 **`세션 하나 = DO 하나`**, **여러 파일의 서로 다른 만료시간을 alarm 하나로 관리**, **동시 업로드 시 quota reservation**, **WebSocket Hibernation**, 이 네 가지입니다. 이 부분만 제대로 설계하면 나머지는 오히려 현재 Python 서버보다 단순해질 가능성이 큽니다. Durable Object의 alarm은 Object당 동시에 하나뿐이고 at-least-once 실행이므로, 삭제 로직을 idempotent하게 만들어야 합니다. [Cloudflare Docs](https://developers.cloudflare.com/durable-objects/api/alarms/?utm_source=chatgpt.com)

그리고 현재 30MB 제한에서는 presigned upload까지 넣지 않는 것이 좋습니다. Cloudflare Free에서도 요청 본문 한도가 100MB이고, R2는 이보다 훨씬 큰 object도 처리할 수 있으므로, **1차 포팅은 Worker→R2 스트리밍으로 단순하게 끝내는 것**이 좋습니다. 나중에 Drop5의 파일 한도를 수백 MB로 올릴 때 direct/presigned 또는 multipart upload로 바꾸면 됩니다. [Cloudflare Docs](https://51e47fea.previews.developers.cloudflare.com/workers/platform/limits/?utm_source=chatgpt.com)