mkdir mpower2_user_add_package
pip-3.6 install --upgrade numpy pandas synapseclient boto3 -t mpower2_user_add_package
pip-3.6 install git+https://github.com/larssono/bridgeclient.git -t mpower2_user_add_package
cp user_add.py .synapseConfig mpower2_user_add_package
cd mpower2_user_add_package
zip -r ../mpower2_user_add_package.zip .
aws s3 cp ../mpower2_user_add_package.zip s3://mpower2-user-add2/mpower2_user_add_package.zip 
aws lambda update-function-code --function-name mpower2-user-add --s3-bucket mpower2-user-add2 --s3-key mpower2_user_add_package.zip
cd ..
rm -r mpower2_user_add_package.zip mpower2_user_add_package/
