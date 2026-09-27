# 服务接口

所有时间使用带时区的 ISO 8601 格式。服务持久化 UTC 时间，按诊所配置的时区解释运营日期。JSON 请求大小上限为 1 MB；无效请求返回稳定的错误码和 HTTP 状态，不向调用方透出数据库异常。

## 登录与诊所隔离

`POST /auth/token` 接受 `staff_id` 和 `password`，返回有效期不超过一天的 Bearer 凭据。除登录与健康检查外，请求必须同时提供 `Authorization: Bearer …` 和 `X-Clinic-ID`。认证失败不区分账号不存在、停用或密码错误；诊所边界之外的数据返回不存在，避免泄露另一诊所的记录。

`POST /auth/logout` 撤销当前凭据。修改员工密码会撤销该员工的全部活动凭据。初始负责人通过命令行创建；没有可直接注册负责人的 HTTP 路由。

## 患者、评估与诊疗计划

- `POST /patients` 建立诊所内患者档案；外部编号在诊所范围内唯一。
- `GET /patients/{patient_id}` 返回最小档案，不返回联系方式密文。
- `POST /patients/{patient_id}/merge` 以两个版本号和书面原因将重复档案标记为合并，并指向保留档案。
- `POST /patients/{patient_id}/assessments` 新建评估草稿；`POST /assessments/{assessment_id}/sign` 由临床岗位签署。
- `POST /patients/{patient_id}/consents` 创建更高版本的授权；`POST /consents/{consent_id}/withdraw` 撤回授权。
- `POST /patients/{patient_id}/plans` 建立计划，医美和体重管理计划必须引用当前对应授权。
- `POST /plans/{plan_id}/{propose|activate|pause|resume|complete|cancel}` 以 `expected_version` 执行带版本保护的状态转换。
- `GET /patients/{patient_id}/weight-series` 返回按观察时间排序的测量值，不生成诊断或治疗建议。每条记录标注来源（患者自报 `patient`、门诊记录 `clinician`、设备导入 `import`），导入记录附带 `origin`（批次编号与原文件行号），`count_by_source` 汇总各来源条数。

评估签署后不可覆盖。就诊病历由章节组成，签署需要主诉、评估和计划三部分；签署后的补充内容成为新版本，原始文字仍保留。

## 门诊外设备测量导入

护理组整理的设备测量文件通过 `POST /imports/measurements` 批量导入，请求体包含 `batch_key`（诊所内唯一的批次键）、`source`（来源说明）、`format_version`（`scale_csv_v1` 或 `weight_json_v1`）和 `content`（文件全文）。每个批次持久化来源、格式版本、内容摘要（SHA-256）和每行的原始行号与内容摘要，可经 `GET /imports/measurements/{batch_id}` 回查。

- 行级处理互不影响：可识别的行写入观察记录（来源标记为 `import`），无法识别患者、单位不符、时间或数值异常的行进入待核对清单，单行问题不会使整批失败，错误数字不会写成正式记录。文件内或跨批次的重复上传只保留首条记录。
- 相同批次键加相同内容重传返回原处理结果（`replayed: true`），不产生新记录；同批次键提交修订内容时生成新修订，`changes` 逐行说明变化（未变、新增导入、追加更正、仍待核对、本次移除等）。
- 修订行数值变化时对原导入记录追加更正（`correction_of`），旧值保持不变；变更患者或测量项目的行不会改写原记录，而是进入待核对清单。
- `GET /imports/review-items?status=pending` 查看待核对清单；`POST /imports/review-items/{id}/resolve` 以 `action`（`resolve` 或 `dismiss`）和书面说明完成核对。
- `POST /observations/{id}/corrections` 对已入账的导入值追加更正记录，需说明原因；原始记录与旧值不被改写。

`scale_csv_v1` 要求表头为 `patient_ref,measured_at,kind,value,unit`，行号含表头从 1 计；`weight_json_v1` 为 `{"rows": [...]}`，行号从 1 计。测量项目接受体重（kg）与腰围（cm）及其常见别名，其余单位一律进入待核对清单。

## 预约、随访与计划节点

创建预约须提供 `Idempotency-Key`，有责任人的预约不能与未结束时段重叠。临时占位到期后由 `POST /appointments/{id}/book` 拒绝确认，过期占位可通过服务方法按限额释放。预约状态按占位、确认、到诊、服务、完成推进；开始服务时产生就诊记录。

随访和计划节点支持领取租约、版本校验、幂等创建、延期和完整处置历史。旧领取者不能以过期令牌提交结果；重新领取不会删除前次领取事件。

## 诊所耗材

- `POST /products` 登记耗材；`POST /products/{product_id}/lots` 按批号入库。
- `POST /stock/reserve` 依据失效日期按先到期先出分批预留，需要 `Idempotency-Key`。
- `POST /stock/{reservation_id}/consume` 记录患者使用；`release` 释放尚未使用的数量。
- `POST /stock/{lot_id}/quarantine`、`recall` 或 `release-quarantine` 记录批次处置及受影响预留。
- `GET /stock/lots` 查看可用数量；`GET /stock/{lot_id}/history` 查看批次流水。

入库、占用、释放与患者使用均进入不可变流水。存在不足时整笔预留回滚；被隔离、召回或在诊所本地日期已过期的批次不能继续使用。

## 不良事件与数据使用

护理人员可报告事件或患者安全关注项；临床岗位复核并记录处置，诊所负责人可作废就诊记录。`GET /audit/verify` 校验诊所哈希链，`GET /audit/diagnostics` 汇报需人工核对的一致性问题，不自动修改业务状态。

`POST /patients/{patient_id}/export` 只在存在有效数据导出授权时返回明确选择的章节。导出字段采用白名单，联系方式密文、凭据和内部合并字段不会导出；相同幂等请求得到相同内容摘要。`GET /reports/daily`、`appointments`、`incidents` 和 `overdue-milestones` 仅返回运营汇总或经岗位授权的工作队列。

## 主要状态

- 计划：草稿 → 提议 → 生效；可暂停和恢复，完成或取消后不能重新激活。
- 预约：占位 → 确认 → 到诊 → 服务中 → 完成；取消和未到诊是独立终态。
- 不良事件：已报告 → 分诊 → 观察 → 已解决 → 关闭。每次处置单独记录操作人和理由。
- 耗材预留：预留 → 释放或核销。库存数量由收货、预留、释放和更正流水求和，不直接改写历史数量。
