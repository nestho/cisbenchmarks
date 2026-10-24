.PHONY: backend frontend

backend:
	cd backend && go run ./cmd/server

frontend:
	cd frontend && npm install && npm run dev

up:
	docker compose up -d

down:
	docker compose down
