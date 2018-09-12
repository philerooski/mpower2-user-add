mkdir mpower2_user_add_package
pip3 install --upgrade cython numpy pandas synapseclient -t mpower2_user_add_package
pip3 install git+https://github.com/larssono/bridgeclient.git -t mpower2_user_add_package
cp user_add.py .synapseConfig mpower2_user_add_package
cd mpower2_user_add_package
zip -r ../mpower2_user_add_package.zip .
aws s3 --profile phil-admin cp ../mpower2_user_add_package.zip s3://mpower2-user-add/mpower2_user_add_package.zip 
aws lambda update-function-code --function-name mpower2-user-add --s3-bucket mpower2-user-add --s3-key mpower2_user_add_package.zip --profile phil-admin
