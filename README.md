使用零知识证明技术实现基于账户模型的隐私交易。

Warning：当前代码仅为原型验证系统，请勿用于生产环境。

***
### 使用说明
1. 生成参数。参数文件位于当前目录下PARAMS目录中。
```
cargo run --release --example gen_params
```
2. 单项测试。
```
cargo run --release --example tree_test
cargo run --release --example bench
```
3. 转账流程集成测试。
```
cargo run --release --example round_test
cargo run --release --example contract_test
```
4. 跟CITA的系统测试
```
cargo run --release --example client
```