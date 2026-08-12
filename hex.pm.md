# Hex.pm 发布维护指南

本文面向 Guomi 维护者，说明当前仓库的版本发布、GitHub Release 与 Hex.pm 发布流程。

## 当前发布方式

仓库使用 [`.github/workflows/release.yml`](.github/workflows/release.yml) 自动发布：

1. 推送与 `mix.exs` 版本一致、形如 `v0.5.2` 的 Git tag。
2. workflow 在 Erlang/OTP 27 与 Elixir 1.18 上编译并运行测试。
3. 测试通过后创建 GitHub Release。
4. 使用仓库 secret `HEX_API_KEY` 构建并发布 Hex 包与文档。

日常 push 与 pull request 的质量检查由 [`.github/workflows/ci.yml`](.github/workflows/ci.yml) 执行。

## 发布前检查

### 1. 更新版本和文档

- 在 `mix.exs` 中更新 `@version`。
- 将 `CHANGELOG.md` 的 `[Unreleased]` 内容归入新版本，并填写发布日期。
- 更新 README 中的安装版本和近期版本说明。
- 确认公开文档与当前 API、CLI 行为一致。

### 2. 运行质量检查

```bash
mix deps.get
mix format --check-formatted
mix compile --warnings-as-errors
mix test
mix credo --strict
mix docs
mix hex.build
```

`mix hex.build` 会显示包元数据与包含文件。当前包应包含：

- `lib/`
- `.formatter.exs`
- `mix.exs`
- `README.md`
- `cli.md`
- `CHANGELOG.md`
- `todo.md`
- `hex.pm.md`
- `LICENSE`

### 3. 检查发布状态

```bash
git status --short
git log -1 --oneline
mix hex.info guomi
```

发布提交应已推送到 `main`，工作区应无意外改动。

## 自动发布

确认版本提交已在 `main` 后创建并推送 tag：

```bash
git tag -a v0.5.2 -m "Release v0.5.2"
git push origin v0.5.2
```

随后在 GitHub Actions 中确认 Release workflow 的 `test`、`release` 和 `publish` 三个 job 均成功。

> Tag 版本必须与 `mix.exs` 中的 `@version` 一致。workflow 不提供手动发布入口，也不会自动修改版本号。

## 手动发布

仅在自动流程不可用且已确认版本内容时使用：

```bash
mix hex.user auth
mix hex.build
mix hex.publish --yes
```

也可分别发布：

```bash
mix hex.publish package --yes
mix hex.publish docs --yes
```

CI 环境通过 `HEX_API_KEY` 认证，本地维护者通常通过 `mix hex.user auth` 认证。

## 发布后验证

1. 检查 [Hex 包页面](https://hex.pm/packages/guomi) 的最新版本和文件列表。
2. 检查 [HexDocs](https://hexdocs.pm/guomi) 的 README、CLI 和模块文档。
3. 检查 GitHub Release 的 tag、标题和自动生成的变更说明。
4. 在临时项目中添加新版本依赖并运行一个 SM3/SM4 冒烟示例。

```elixir
def deps do
  [{:guomi, "~> 0.5.2"}]
end
```

## 撤回与替换

Hex 对撤回和替换有时间限制，执行前应先查看当前 Hex 官方规则：

```bash
mix help hex.publish
mix help hex.package
```

常用命令：

```bash
mix hex.publish package --replace
mix hex.publish --revert 0.5.2
```

已被用户安装的错误版本不应静默覆盖。通常更稳妥的处理方式是发布新的补丁版本，并在 `CHANGELOG.md` 和 GitHub Release 中说明修复内容。

## 发布故障排查

### `HEX_API_KEY` 缺失或无效

在 GitHub 仓库的 Actions secrets 中更新 `HEX_API_KEY`，然后重新运行失败的 publish job。

### Tag 与包版本不一致

不要移动已公开使用的 tag。修正 `mix.exs` 与变更日志后，创建新的版本提交和新 tag。

### 文档未更新

确认 `mix.exs` 的 `docs.extras` 与 `package.files` 包含目标文档，然后运行：

```bash
mix docs
mix hex.publish docs --yes
```

## 参考

- [Hex 发布指南](https://hex.pm/docs/publish)
- [Hex 使用指南](https://hex.pm/docs/using-hex)
- [Semantic Versioning](https://semver.org/)
