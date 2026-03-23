# Hex.pm 提交步骤

本文档描述如何将 Guomi 包发布到 Hex.pm。

## 前置准备

### 1. 注册 Hex.pm 账号

访问 https://hex.pm 并注册账号。

### 2. 安装 Hex 本地工具

```bash
mix local.hex
```

### 3. 认证 Hex 账号

```bash
mix hex.user auth
```

按提示输入用户名、邮箱和密码。

---

## 配置 mix.exs

确保 `mix.exs` 包含以下必要字段：

### 必填字段

```elixir
def project do
  [
    app: :guomi,
    version: "0.1.0",
    description: "Guomi cryptographic algorithms for Elixir (SM2/SM3/SM4)",
    package: package(),
    deps: deps()
  ]
end
```

### package/0 函数

```elixir
defp package do
  [
    licenses: ["MIT"],
    links: %{
      "GitHub" => "https://github.com/your-username/guomi"
    },
    # 可选：指定包含的文件
    files: ~w(lib .formatter.exs mix.exs README.md LICENSE)
  ]
end
```

### 可选但推荐

```elixir
def project do
  [
    # ...
    source_url: "https://github.com/your-username/guomi",
    # 文档生成配置（使用 ex_doc）
    name: "Guomi",
    docs: &docs/0
  ]
end

defp docs do
  [
    main: "readme",
    extras: ["README.md"],
    source_url: "https://github.com/your-username/guomi"
  ]
end
```

---

## 发布前检查

### 1. 构建本地 tarball

生成 `.tar` 包并查看包含的文件和元信息：

```bash
mix hex.build
```

输出会显示所有将被打包的文件、版本、许可证、链接等信息。

解压 tarball 检查内容：

```bash
tar -tf guomi-0.1.0.tar
```

### 2. 运行测试

确保所有测试通过：

```bash
mix test
```

### 5. 检查依赖

Hex.pm 不允许发布有未解析依赖的包：

```bash
mix deps.get
mix deps.compile
```

### 6. 生成并检查文档

```bash
mix docs
```

打开 `doc/index.html` 检查文档是否正确生成。

---

## 发布流程

### 发布到 Hex.pm

```bash
mix hex.publish
```

### 发布包

```bash
mix hex.publish package 
```

### 仅发布文档

```bash
mix hex.publish docs
```

### 覆盖版本

#### 时间窗口规则

| 包的类型 | 可修改/撤销的时间窗口 |
| :--- | :--- |
| **首次发布的全新包** | 发布后 **24小时** 内  |
| **已有包的新版本** | 发布后 **1小时** 内  |

```sh
mix hex.publish package --replace
mix hex.publish --replace
```

### 撤销

```sh
mix hex.publish --revert 1.0.0
```

---

## 版本管理

### 语义化版本 (SemVer)

遵循 `MAJOR.MINOR.PATCH` 格式：

- **MAJOR**: 不兼容的 API 变更
- **MINOR**: 向后兼容的功能新增
- **PATCH**: 向后兼容的 Bug 修复

### 更新版本

在 `mix.exs` 中更新 `version` 字段：

```elixir
version: "0.2.0"  # 从 0.1.0 升级
```

### 发布新版本

```bash
mix hex.publish
```

---

## 常见问题

### 发布失败：版本已存在

Hex.pm 不允许覆盖已发布的版本。需要：

1. 增加版本号
2. 重新发布

### 发布失败：依赖问题

确保所有依赖：
- 也在 Hex.pm 上发布
- 版本约束正确

### 撤销发布

仅在发布后 **1 小时内** 可以撤销：

```bash
mix hex.retract guomi 0.1.0
```

超过 1 小时需联系 Hex.pm 管理员。

### 转移所有权

添加其他维护者：

```bash
mix hex.owner add your-username
```

---

## 发布后验证

### 1. 检查 Hex.pm 页面

访问 https://hex.pm/packages/guomi 确认包已发布。

### 2. 本地测试安装

```bash
mix hex.search guomi
```

或查看已发布的包信息：

```bash
mix hex.info guomi
```

### 3. 验证文档

访问 https://hexdocs.pm/guomi 查看生成的文档。

---

## 最佳实践

1. **CHANGELOG**: 维护变更日志，记录每个版本的改动
2. **Git Tag**: 发布后打标签
   ```bash
   git tag v0.1.0
   git push origin v0.1.0
   ```
3. **CI/CD**: 使用 GitHub Actions 等自动测试和发布
4. **向后兼容**: 尽量避免破坏性变更，特别是在 1.0 之前

---

## 参考链接

- [Hex.pm 官方文档](https://hex.pm/docs)
- [Hex 使用指南](https://hex.pm/docs/using)
- [发布包指南](https://hex.pm/docs/publish)
- [语义化版本规范](https://semver.org/)
