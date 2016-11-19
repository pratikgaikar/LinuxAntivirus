files=$(find $1 -type d \( -path ./.git -o \
                  -path ./log -o \
                  -path ./public -o \
                  -path ./tmp \) -prune -o \
       ! -type d -print)
#echo $files
for file in $files
do
    sha1sum $file >>/tmp/sha1sum.txt
     #echo $file
done
