rm -rf ./target
mkdir target
docker run --rm -v $PWD:/documents curs/asciidoctor-od asciidoctor doc/pages/manual.adoc -o target/index.html