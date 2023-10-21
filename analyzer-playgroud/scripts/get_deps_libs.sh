DEPS_LIB=$(find $(pwd)/deps/**/lib/ -type d)
GCC_DEPS_FLAGS=""

for path in $DEPS_LIB
do
    LIB_NAME=$(echo "$path" | grep -oE '/([^/]+)/lib' | cut -d'/' -f2)
    GCC_DEPS_FLAGS+="-L$path -Wl,-rpath,$path "
    GCC_DEPS_FLAGS+="-l$LIB_NAME "
done

echo $GCC_DEPS_FLAGS