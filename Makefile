BINARY := tpios

.PHONY: all build fmt vet clean run

all: build

build: fmt vet
	go build -o $(BINARY) .

fmt:
	gofmt -l . | (! grep .)

vet:
	go vet ./...

run: build
	./$(BINARY) $(ARGS)

clean:
	rm -f $(BINARY)
