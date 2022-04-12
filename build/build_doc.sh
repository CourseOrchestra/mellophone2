[ ! -d "target" ] && mkdir target
docker run --rm -v $PWD:/documents/ curs/asciidoctor-od [ ! -d "target/doc" ] && rm target/doc -rf
docker run --rm -v $PWD:/documents/ curs/asciidoctor-od cp doc target -r
docker run --rm -v $PWD:/documents/ curs/asciidoctor-od bash build/antorize.sh
