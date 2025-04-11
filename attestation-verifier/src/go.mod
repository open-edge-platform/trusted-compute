module github.com/open-edge-platform/trusted-compute/attestation-verifier/src

go 1.18

require (
	github.com/DATA-DOG/go-sqlmock v1.4.1
	github.com/Waterdrips/jwt-go v3.2.1-0.20200915121943-f6506928b72e+incompatible
	github.com/antchfx/jsonquery v1.1.4
	github.com/beevik/etree v1.1.0
	github.com/cloudflare/cfssl v1.5.0
	github.com/davecgh/go-spew v1.1.1
	github.com/google/renameio v1.0.1
	github.com/google/uuid v1.3.0
	github.com/gorilla/handlers v1.4.2
	github.com/gorilla/mux v1.7.3
	github.com/hashicorp/golang-lru v0.5.1
	github.com/jinzhu/copier v0.3.0
	github.com/jinzhu/gorm v1.9.16
	github.com/joho/godotenv v1.3.0
	github.com/lib/pq v1.3.0
	github.com/mattermost/xml-roundtrip-validator v0.0.0-20201213122252-bcd7e1b9601e
	github.com/nats-io/jwt/v2 v2.5.0
	github.com/nats-io/nats.go v1.28.0
	github.com/nats-io/nkeys v0.4.6
	github.com/onsi/ginkgo v1.16.4
	github.com/onsi/ginkgo/v2 v2.1.3
	github.com/onsi/gomega v1.17.0
	github.com/pkg/errors v0.9.1
	github.com/russellhaering/goxmldsig v1.2.0
	github.com/sirupsen/logrus v1.7.0
	github.com/spf13/viper v1.7.1
	github.com/stretchr/testify v1.8.3
	github.com/vmware/govmomi v0.22.2
	github.com/xeipuuv/gojsonschema v1.2.0
	golang.org/x/crypto v0.17.0
	golang.org/x/net v0.17.0
	golang.org/x/sync v0.1.0
	gopkg.in/yaml.v3 v3.0.1
)

require (
	github.com/antchfx/xpath v1.1.7 // indirect
	github.com/form3tech-oss/jwt-go v3.2.3+incompatible // indirect
	github.com/fsnotify/fsnotify v1.4.9 // indirect
	github.com/golang/groupcache v0.0.0-20210331224755-41bb18bfe9da // indirect
	github.com/golang/protobuf v1.5.3 // indirect
	github.com/google/certificate-transparency-go v1.0.21 // indirect
	github.com/hashicorp/hcl v1.0.0 // indirect
	github.com/jinzhu/inflection v1.0.0 // indirect
	github.com/jmoiron/sqlx v1.2.0 // indirect
	github.com/jonboulle/clockwork v0.2.2 // indirect
	github.com/klauspost/compress v1.16.7 // indirect
	github.com/magiconair/properties v1.8.1 // indirect
	github.com/mattn/go-sqlite3 v1.14.14 // indirect
	github.com/mitchellh/mapstructure v1.1.2 // indirect
	github.com/nats-io/nats-server/v2 v2.9.23 // indirect
	github.com/nats-io/nuid v1.0.1 // indirect
	github.com/nxadm/tail v1.4.8 // indirect
	github.com/pelletier/go-toml v1.2.0 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/rogpeppe/go-internal v1.9.0 // indirect
	github.com/spf13/afero v1.9.2 // indirect
	github.com/spf13/cast v1.3.0 // indirect
	github.com/spf13/jwalterweatherman v1.0.0 // indirect
	github.com/spf13/pflag v1.0.5 // indirect
	github.com/stretchr/objx v0.5.0 // indirect
	github.com/subosito/gotenv v1.2.0 // indirect
	github.com/xeipuuv/gojsonpointer v0.0.0-20180127040702-4e3ac2762d5f // indirect
	github.com/xeipuuv/gojsonreference v0.0.0-20180127040603-bd5ef7bd5415 // indirect
	golang.org/x/sys v0.15.0 // indirect
	golang.org/x/text v0.14.0 // indirect
	google.golang.org/protobuf v1.30.0 // indirect
	gopkg.in/ini.v1 v1.51.0 // indirect
	gopkg.in/tomb.v1 v1.0.0-20141024135613-dd632973f1e7 // indirect
	gopkg.in/yaml.v2 v2.4.0 // indirect
)

replace github.com/vmware/govmomi => github.com/arijit8972/govmomi v0.22.2-0.20230329053902-9de0bf83add8
