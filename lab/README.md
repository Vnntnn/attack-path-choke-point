# Hybrid Lab Environment (Terraform + LocalStack + Cartography + On-Prem Docker)

ชุดการทดลองสภาพแวดล้อมจำลอง (Lab) สำหรับสร้างกราฟการโจมตีจากทรัพยากรจริงทั้งสองฝั่ง ได้แก่ฝั่งคลาวด์ (Terraform + LocalStack + Cartography + Neo4j) และฝั่งเครือข่ายภายในองค์กร (Docker Compose + `nmap` + SSH dictionary attack) แล้วแปลงเข้าสู่สคีมา edge list ของแพ็กเกจ `attackpath`

## โครงสร้างและการเลือกใช้เครื่องมือใน Lab

- **ฝั่ง Cloud (`LocalStack 4.4.0` + `Terraform` + `Cartography`)**:
  เนื่องจากการทดสอบบนบัญชี AWS Academy Learner Lab มีข้อจำกัดระดับบัญชีที่บล็อกคำสั่ง `iam:CreateRole` และ `iam:CreateUser` รวมถึงมี Service Control Policy (SCP) ระดับองค์กรที่บล็อก `s3:GetBucketObjectLockConfiguration` จึงใช้ `localstack/localstack:4.4.0` เพื่อจำลอง AWS API สำหรับสร้าง IAM, S3 และ Security Group ด้วย Terraform แล้วดึงข้อมูลเข้า Neo4j ผ่าน Cartography
  *(หมายเหตุ: ต้องระบุอิมเมจเวอร์ชัน `4.4.0` เนื่องจากเวอร์ชัน `:latest` มีการบังคับใช้ `LOCALSTACK_AUTH_TOKEN`)*
  ใน `lab/terraform` แยก Terraform workspace ไว้สองชุดคือ `default` (สำหรับ LocalStack) และ `real-aws` (สำหรับกรณีรันกับบัญชี AWS ปกติ) โดยตั้งค่าผ่านไฟล์ `terraform.tfvars`

- **ฝั่ง On-Premise (`Docker Compose` + `nmap` + `paramiko`)**:
  จำลองโฮสต์ 2 เครื่อง (`lab-onprem-dmz` และ `lab-onprem-internal`) บนเครือข่าย bridge เดียวกันโดยไม่มีการแบ่งโซน (`lab/onprem/docker-compose.yml`) เพื่อแทนสภาพแวดล้อมแบบ `flat-vlan-no-segmentation` จากนั้นใช้ `nmap` ตรวจสอบพอร์ตที่เปิด และใช้ `paramiko` ทดสอบรหัสผ่าน SSH ที่อ่อนแอ (`weak-ssh-credentials`) ก่อนอ่านไฟล์ `/root/.aws/credentials` บนเครื่องภายใน

- **การเชื่อมโยงเส้นทางข้ามโดเมน (`aws-key-on-host`)**:
  `lab/terraform/main.tf` สร้าง IAM user และ access key บน LocalStack แล้วส่งค่า key ID ไปเก็บไว้ใน `/root/.aws/credentials` ของคอนเทนเนอร์ `lab-onprem-internal` ตัวแปลงข้อมูล `lab/exporter/export_graph.py` จะสร้าง edge ข้ามโดเมน `aws-key-on-host` ก็ต่อเมื่อรหัส access key ที่อ่านได้จากเครื่องฝั่ง on-premise ตรงกับโหนด `AccountAccessKey` ที่ Cartography ดึงขึ้นมาจากฝั่งคลาวด์และบันทึกอยู่ใน Neo4j เท่านั้น

## ขั้นตอนการรันเพื่อทำซ้ำผล (Reproduce)

```bash
# 1. รัน LocalStack และ Neo4j 5
docker run -d --name localstack -p 4566:4566 -e SERVICES=s3,iam,sts,ec2 \
  localstack/localstack:4.4.0
docker run -d --name lab-neo4j -p 7474:7474 -p 7687:7687 \
  -e NEO4J_AUTH=neo4j/<password> neo4j:5

# 2. สร้างทรัพยากรฝั่งคลาวด์ด้วย Terraform
cd lab/terraform && terraform init && terraform apply -auto-approve && cd -

# 3. ติดตั้งและรัน Cartography ในแยก virtual environment ของ lab
uv venv lab/.venv --python 3.13
uv pip install --python lab/.venv cartography paramiko
uv pip install --python lab/.venv -e .

export LAB_NEO4J_PW=<password>
AWS_ENDPOINT_URL=http://localhost:4566 AWS_ACCESS_KEY_ID=test \
AWS_SECRET_ACCESS_KEY=test AWS_DEFAULT_REGION=us-east-1 AWS_MAX_ATTEMPTS=2 \
lab/.venv/bin/python lab/run_sync.py \
  --neo4j-uri bolt://localhost:7687 --neo4j-user neo4j \
  --neo4j-password-env-var LAB_NEO4J_PW \
  --selected-modules aws --aws-requested-syncs s3,iam,ec2:security_group

# 4. รันคอนเทนเนอร์ฝั่ง on-premise และส่งออกกราฟรวมสองฝั่ง
export LEAKED_ACCESS_KEY_ID=$(terraform -chdir=lab/terraform output -raw leaked_access_key_id)
docker compose -f lab/onprem/docker-compose.yml up -d
lab/.venv/bin/python lab/exporter/export_graph.py --neo4j-password <password>
# หากต้องการส่งออกเฉพาะฝั่งคลาวด์อย่างเดียวสามารถเติมพารามิเตอร์ --skip-onprem

# 5. รันวิเคราะห์จุดตัดด้วยโค้ดชุดเดียวกับกราฟจำลอง
uv run python -c "
from attackpath import graph as G, weights, chokepoints as cp
import random
g = G.from_csv('lab/lab_graph.csv',
                entry_nodes=[('internet','anon')],
                target_nodes=[('role:itis2026-lab-cross-account-trust-role','admin'),
                               ('user:itis2026-lab-leaked-key-user','admin')])
weights.assign(g, 'fitted', random.Random(1))
G.validate_weights(g)
print('global:', cp.post_dominators(g, G.entries(g), G.targets(g)))
print('per_target:', cp.per_target_chokepoints(g, G.entries(g), G.targets(g)))
"
```

### กรณีรีสตาร์ต LocalStack
เนื่องจาก LocalStack community ไม่เก็บสถานะข้ามการรีสตาร์ต หากรีสตาร์ตคอนเทนเนอร์จะต้องสั่ง `terraform apply` และสร้างคอนเทนเนอร์ฝั่ง on-premise ใหม่เพื่อให้ค่า `LEAKED_ACCESS_KEY_ID` บนเครื่องตรงกับที่สร้างใหม่ในคลาวด์:

```bash
terraform -chdir=lab/terraform apply -auto-approve
export LEAKED_ACCESS_KEY_ID=$(terraform -chdir=lab/terraform output -raw leaked_access_key_id)
docker compose -f lab/onprem/docker-compose.yml up -d --force-recreate
```

## รายละเอียดเพิ่มเติมของ Pipeline

- **`lab/run_sync.py`**: โมดูล `iam.sync()` ของ Cartography มีการเรียก API `GenerateServiceLastAccessedDetails` เสมอ ซึ่ง LocalStack community ตอบกลับเป็นรหัส `501` และทำให้ขั้นตอนการดึงข้อมูลค้าง `lab/run_sync.py` จึงทำหน้าที่ข้ามเฉพาะการเรียกฟังก์ชันย่อยดังกล่าวเพื่อให้ซิงก์ข้อมูล IAM, S3 และ Security Group เข้า Neo4j ได้ตามปกติ
- **ข้อจำกัดของ Cartography กับ Wildcard Principal**: ตัวแปลงนโยบายของ Cartography (`_parse_principal_entries`) สร้างความสัมพันธ์ `TRUSTS_AWS_PRINCIPAL` เฉพาะเมื่อระบุ ARN ของผู้รับสิทธิ์ชัดเจนเท่านั้น หากกำหนด `"Principal": "*"` (`iam-trust-wildcard-principal`) จะไม่สร้างความสัมพันธ์ใน Neo4j ใน `lab/terraform/main.tf` จึงสร้างทั้ง role ที่เป็น wildcard และ role ที่ระบุ ARN ข้ามบัญชี (`iam-trust-missing-external-id`) ควบคู่กัน
- **ลักษณะของกราฟที่ได้ (`lab/lab_graph.json`, `lab/lab_graph.csv`)**:
  ประกอบด้วย 9 โหนด, 8 เส้นเชื่อม, จุดเข้าเริ่มต้น 1 จุด (`("internet", "anon")`) และเป้าหมาย 2 จุดที่อยู่คนละกิ่งกัน จึงทำให้ชุด global post-dominator เป็นเซตว่าง ในขณะที่ `per_target_chokepoints` สามารถระบุจุดตัดของแต่ละเป้าหมายแยกตามกิ่งได้อย่างถูกต้อง
