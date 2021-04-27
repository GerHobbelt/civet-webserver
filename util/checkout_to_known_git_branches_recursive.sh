#! /bin/bash
#
# Generated by the utility: /z/util/collect_git_checked_out_branch_recusively.sh 
#
# Checkout each git repository to the given branch/commit or list them
#

mode=h;
while getopts ":hlc" opt ; do
  #echo opt+arg = "$opt$OPTARG"
  case "$opt$OPTARG" in
  l )
    mode=h;
    ;;

  c )
    mode=c;
    ;;

  r )
    mode=r;
    ;;

  * )
    cat <<EOH
checkout_to_known_git_branches_recursive.sh options

Options:

-h      : print this help 
-l      : LIST the branch/commit for each git repository (directory) registered in this script.
-c      : CHECKOUT each git repository to the BRANCH registered in this script.
-r      : CHECKOUT/REVERT each git repository to the COMMIT registered in this script.

Note:

Use the '-r' option to set each repository to an exact commit position, which is useful if,
for instance, you wish to reproduce this registered previous software state (which may 
represent a software release) which you wish to analyze/debug.

EOH
    exit 1;
    ;;
  esac
done

if test "$mode" = "h" ; then
  cat <<EOH

Git repository directory                    :: commit hash                         / branch name
--------------------------------------------::--------------------------------------------------
EOH
fi



# args: DIR COMMIT [BRANCH]
git_repo_checkout_branch() {
  if test "$mode" = "c" || test "$mode" = "r" ; then
    if test -d "$1" ; then
      pushd "$1"                                                               2> /dev/null  > /dev/null
      if test "$mode" = "c" ; then
        if test -n "$3" ; then
          # make sure the branch is created locally and is a tracking branch:
          git branch --track "$3" "remotes/origin/$3"                            2> /dev/null  > /dev/null
          git checkout "$3"
        else
          git checkout master
        fi
      else
        git checkout "$2"
      fi
      popd                                                                     2> /dev/null  > /dev/null
    fi
  else
    if test -d "$1" ; then
      printf "%-43s :: %s / %s\n" "$1" "$2" "$3"
    else
      printf "%-43s :: %s / %s\n" "[DIRECTORY DOES NOT EXIST!] $1" "$2" "$3"
    fi
  fi
}


#
# Make sure we switch to the utility directory as all the relative paths for the repositories
# are based off that path!
#
pushd $(dirname $0)                                                            2> /dev/null  > /dev/null



#
# The registered repositories:
#

git_repo_checkout_branch "../docs/wiki" bff7d05c87ce16fb0debd80272eac238984fd905 master
git_repo_checkout_branch "../docs/wiki-vanilla" 41351a9d314ff29c5c83f0ee2478583b33f58e31 master
git_repo_checkout_branch "../src/thirdparty/duktape" 5252b7a50611a3cb8bfcd6856b6a4a899bc622ed master
git_repo_checkout_branch "../src/thirdparty/lua" ef9f07c408cedff07da40fb430b12b6cc120cae1 master
git_repo_checkout_branch "../src/thirdparty/luafilesystem" 7c6e1b013caec0602ca4796df3b1d7253a2dd258 master
git_repo_checkout_branch "../src/thirdparty/popt" 45795290fce544204939166cea6677ed9165c29a master
git_repo_checkout_branch "../src/thirdparty/pthread-win32" 17a7464505e683cfa127a7a2ca4ba88ba899f2c7 master
git_repo_checkout_branch "../src/thirdparty/selectable-socketpair" 8a5ff916643d2674414dcf7ada62c5dab708c01b master
git_repo_checkout_branch "../src/thirdparty/upskirt" 739b2f0a0d7dc416d47b3c5976154e23f39d6b9c master

# --- all done ---

popd                                                                           2> /dev/null  > /dev/null
