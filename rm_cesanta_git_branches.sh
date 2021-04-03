#! /bin/bash
#
# Remove GNU/cesanta branches so we cannot accidentally merge or cherrypick from them!
# 

# commit hash is first GNU commit
R=218428662e6f8d30a83cf8a89f531553f1156d25

for f in $( git tag -l ; git branch -a ) ; do 
	echo "$f"
	X=$(git merge-base $R "$f" ) 
	#echo "X=[$X]" 
	if test "$X" = "$R" ; then 
		echo GNU 
		git branch -D "$f" 
		git update-ref -d "refs/$f" 
		git tag -d "$f" 
		#git push origin --delete "$f" 
	else 
		echo CIVETWEB 
	fi
done
