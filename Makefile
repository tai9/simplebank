network:
	docker network create bank-network

postgres:
	docker run --name postgres12 --network bank-network -p 5432:5432  -e POSTGRES_USER=root -e POSTGRES_PASSWORD=secret -d postgres

createdb:
	docker exec -it postgres12 createdb --username=root --owner=root simple_bank

dropdb:
	docker exec -it postgres12 dropdb simple_bank

migrations:
	migrate create -ext sql -dir db/migration -format unix $(name)

# postgresql://root:simplebank@simple-bank.cfaez8hpnico.us-west-2.rds.amazonaws.com:5432/simple_bank
migrateup:
	migrate -path db/migration -database "postgresql://root:secret@localhost:5432/simple_bank?sslmode=disable" -verbose up

migratedown:
	migrate -path db/migration -database "postgresql://root:secret@localhost:5432/simple_bank?sslmode=disable" -verbose down

sqlc:
	sqlc generate

test:
	go test -v -cover ./...

server:
	go run main.go

mock:
	mockgen -package mockdb -destination db/mock/store.go github.com/tai9/simplebank/db/sqlc Store

.PHONY: network postgres createdb dropdb migrations migrateup migratedown sqlc test server mock