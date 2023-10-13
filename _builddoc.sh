rm -rf ./target-doc
mkdir target-doc
docker run --rm -v $PWD:/documents curs/asciidoctor-od asciidoctor doc/pages/manual.adoc -o target-doc/index.html