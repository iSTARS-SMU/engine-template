# trustchain-sdk (Python)

学生写 engine 的工具包。发布为 pip 包 `trustchain-sdk`。

## 提供什么

| module | 作用 |
|---|---|
| `engine.py` | `EngineApp` 基类。学生继承 + 实现 `run()` + 调 `build_app()` |
| `context.py` | `RunContext` 实现。per-invoke 构造 |
| `secrets.py` | `SecretsProxy` — attribute-based + whitelist |
| `llm.py` | `LLMClient` — `ctx.llm.chat(...)` 统一 LLM 入口 |
| `testing.py` | `MockContext` + 其它测试辅助 |
| `cli.py` | `trustchain-sdk new engine --stage ... --name ...` 脚手架 |

## SDK 自动做的事
学生只写 `run()`;SDK 包办 FastAPI `/invoke`/`/schema`/`/healthz`、事件 POST(不带 seq)、secret 过滤注入、LLM 调用计量脱敏、tool 客户端、超时、cancel。

详细 API 表:[spec.md §6 SDK 设计](../../../doc/spec.md)。
HTTP 行为:[engine-contract.md](../../../doc/engine-contract.md)。

## 依赖
- `trustchain-contracts`
- `fastapi` / `uvicorn`(build_app)
- `httpx`(内部用,engine 代码不许直接用)
- `pydantic`
