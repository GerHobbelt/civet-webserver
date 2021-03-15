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

git_repo_checkout_branch "../../../../../../../../../w/Projects/sites/library.visyond.gov/80/lib/tooling/qiqqa/MuPDF/thirdparty/owemdjee/civet-webserver/docs/wiki" e3f84c6a123bb764416d5ac1ac67e0592fe521fc master
git_repo_checkout_branch "../../../../../../../../../w/Projects/sites/library.visyond.gov/80/lib/tooling/qiqqa/MuPDF/thirdparty/owemdjee/civet-webserver/docs/wiki-vanilla" e099d4dc6c9e1c3a02fd31069294c902df9a020c master
git_repo_checkout_branch "../../../../../../../../../w/Projects/sites/library.visyond.gov/80/lib/tooling/qiqqa/MuPDF/thirdparty/owemdjee/civet-webserver/src/thirdparty/popt" 45795290fce544204939166cea6677ed9165c29a master
git_repo_checkout_branch "../../../../../../../../../w/Projects/sites/library.visyond.gov/80/lib/tooling/qiqqa/MuPDF/thirdparty/owemdjee/civet-webserver/src/thirdparty/pthread-win32" 034d9bd32260ccb534576da39b950dd740ec02df master
git_repo_checkout_branch "../../../../../../../../../w/Projects/sites/library.visyond.gov/80/lib/tooling/qiqqa/MuPDF/thirdparty/owemdjee/civet-webserver/src/thirdparty/selectable-socketpair" 8a5ff916643d2674414dcf7ada62c5dab708c01b master
git_repo_checkout_branch "../../../../../../../../../w/Projects/sites/library.visyond.gov/80/lib/tooling/qiqqa/MuPDF/thirdparty/owemdjee/civet-webserver/src/thirdparty/upskirt" bcd5a37d11226907c5003e9b54002832d342d852 master

# --- all done ---

popd                                                                           2> /dev/null  > /dev/null

