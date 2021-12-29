
BASEDIR="$( cd "$(dirname "$0")" ; pwd -P )"
DOCKER_FILE_DIR=$BASEDIR/dist/src/main/docker

if [ -d "out_bin/" ]; then

   echo "Removing out/bin ..."
   rm -rf out_bin/
fi
if [ -d "tvault_final/" ]; then

   echo "Removing tvault_final/ ..."
   rm -rf tvault_final/
fi
if [ -f "tvault_all.tar.gz" ]; then
   echo "Removing tvault_all.tar.gz ..."
   rm -f tvault_all.tar.gz
fi

cd $DOCKER_FILE_DIR
if [ -f "tvault_all.tar.gz" ]; then
    echo "Removing tvault_all.tar.gz from dockerfile ..."
    rm -f tvault_all.tar.gz
fi
cd $BASEDIR




echo "Cleaning up API"
cd $BASEDIR/tvaultapi
mvn clean
cd $BASEDIR
mvn help:evaluate -Dexpression=settings.localRepository | grep -i ".m2"  #to download the depedency to evaluate,otherwise fails
sleep 1m

REP_LOC=$(mvn help:evaluate -Dexpression=settings.localRepository | grep -i ".m2")
cd -- "$REP_LOC"
echo "Repositories available are:"
ls
cd ..
echo "Removing REPOSITORY FROM $REP_LOC ..."
rm -rf repository/
cd $BASEDIR
# cd ~/.m2/
# echo "Removing .m2/repository/ ..."
# rm -rf repository/
# cd $BASEDIR


echo "Cleaning up UI"

   UI_DIR=$BASEDIR/tvaultuiv2
   cd $UI_DIR
   echo "Clean up existing node_modules directory..."
   echo "Removing $UI_DIR/node_modules/ ..."
   rm -rf node_modules
   rm -rf build
   echo "Completed removing the existing node_modules and build directory..."
   cd $BASEDIR


echo "-----------------------------------------------------"
echo "Completed Successfully"
echo "-----------------------------------------------------"