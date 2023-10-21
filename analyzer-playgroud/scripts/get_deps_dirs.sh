DEPS_INCLUDE=$(find deps/**/include/ -type d)
GCC_DEPS_FLAGS="-I./src "

for path in $DEPS_INCLUDE
do
    GCC_DEPS_FLAGS+="-I$path "
done

echo $GCC_DEPS_FLAGS