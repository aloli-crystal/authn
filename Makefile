.PHONY: all deps spec test clean

# Cible par défaut : installer les dépendances et lancer les tests
all: deps spec

# Installe les dépendances Crystal (shards)
deps:
	shards install

# Lance la suite de tests
spec:
	crystal spec

# Alias de spec
test: spec

# Supprime les artefacts de compilation
clean:
	rm -rf .crystal lib
