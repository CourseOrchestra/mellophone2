[ -d "target/antora" ] && rm target/antora -rf
cp build/antora target -r
pushd target/antora || exit
mkdir modules
mkdir modules/ROOT
mkdir modules/ROOT/partials
mkdir modules/ROOT/pages
cp ../../doc/* modules/ROOT/partials -r
cp ../../build/antora/nav.adoc modules/ROOT
find ./modules/ROOT/partials/pages -name '*.adoc' -exec  sh -c \
  $'for f; \
    do
      fn="$(basename $f)"
      sed "s/somefile\.adoc/$fn/g" ../../build/antora/page-template.adoc >modules/ROOT/pages/$fn
    done' \
  sh {}  +
rm modules/ROOT/pages/manual.adoc
echo "Set dummy git repository in Antora"
git init .
touch .gitignore
git add .gitignore
git config user.email "you@example.com"
git commit -m 'initialize repository'
