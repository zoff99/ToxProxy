#! /bin/bash

_HOME2_=$(dirname $0)
export _HOME2_
_HOME_=$(cd $_HOME2_;pwd)
export _HOME_

basedir="$_HOME_""/../"

cd "$basedir"

if [[ $(git status --porcelain --untracked-files=no) ]]; then
	echo "ERROR: git repo has changes."
	echo "please commit or cleanup the git repo."
	exit 1
else
	echo "git repo clean."
fi


f1="src/ToxProxy.c"

cur_m_version=$(cat "$f1" | grep 'char global_version_string'|grep -v ASAN | \
	sed -e 's#^.*= "##' | \
	sed -e 's#".*$##')

echo "$cur_m_version"
next_m_version=$(echo "$cur_m_version"|awk -F. -v OFS=. 'NF==1{print ++$NF}; NF>1{if(length($NF+1)>length($NF))$(NF-1)++; $NF=sprintf("%0*d", length($NF), ($NF+1)%(10^length($NF))); print}')

echo "$next_m_version"

v_major=$(echo "$next_m_version" | cut -d. -f1)
v_minor=$(echo "$next_m_version" | cut -d. -f2)
v_patchlevel=$(echo "$next_m_version" | cut -d. -f3)

sed -i -E 's/(global_version_string\[\] = ")[^-]*(-ASAN";)/\1'"$next_m_version"'\2/' "$f1"
sed -i -E 's/(global_version_string\[\] = ")[^-]*(";)/\1'"$next_m_version"'\2/' "$f1"

sed -i -e 's#define VERSION_MAJOR .*$#define VERSION_MAJOR '"$v_major"'#' "$f1"
sed -i -e 's#define VERSION_MINOR .*$#define VERSION_MINOR '"$v_minor"'#' "$f1"
sed -i -e 's#define VERSION_PATCH .*$#define VERSION_PATCH '"$v_patchlevel"'#' "$f1"

commit_message="new version ""$next_m_version"
tag_name='v'"$next_m_version"

git commit -m "$commit_message" "$f1"
git tag -a "$tag_name" -m "$tag_name"




