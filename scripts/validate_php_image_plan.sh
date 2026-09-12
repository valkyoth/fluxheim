#!/usr/bin/env sh
set -eu

root="$(git rev-parse --show-toplevel)"
cd "$root"

required_modules=packaging/container/php-required-modules.txt
manifests="
packaging/container/php-wolfi-runtime-packages.txt
packaging/container/php-alpine-runtime-packages.txt
packaging/container/php-debian-runtime-packages.txt
packaging/container/php-suse-bci-runtime-packages.txt
"

for file in $required_modules $manifests; do
    test -s "$file"
    if [ "$(sort "$file" | uniq -d | wc -l)" -ne 0 ]; then
        echo "PHP image plan: duplicate entry in $file" >&2
        exit 1
    fi
done

for module in mysqli mysqlnd pdo_mysql gd intl mbstring zip; do
    grep -Fqx "$module" "$required_modules"
done

grep -Fq 'registry.suse.com/bci/php:8@sha256:' containers/Containerfile.suse-bci
grep -Fq 'packaging/container/php-suse-bci-runtime-packages.txt' .github/workflows/images.yml
grep -Fq 'PROFILE}" == "php" && "${VARIANT}" == "suse-micro' .github/workflows/images.yml
grep -Fq 'PROFILE}" != "php" && "${VARIANT}" == "suse-bci' .github/workflows/images.yml

for variant in wolfi alpine debian suse-bci; do
    grep -Fq "$variant)" scripts/smoke_fluxheim_php_images.sh
done

for containerfile in \
    containers/Containerfile.wolfi \
    containers/Containerfile.alpine \
    containers/Containerfile.debian \
    containers/Containerfile.suse-bci
do
    grep -Fq 'COPY packaging/default/index.php /srv/fluxheim/index.php' "$containerfile"
done

echo "PHP image plan: ok"
