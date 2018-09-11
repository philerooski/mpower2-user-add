mkdir mpower2_user_add_package
pip install synapseclient -t mpower2_user_add_package
pip install git+https://github.com/larssono/bridgeclient.git -t mpower2_user_add_package
cp user_add.py main.py .synapseConfig mpower2_user_add_package
cd mpower2_user_add_package
#zip -r ../mpower2_user_add_package.zip .
#aws s3 cp mpower2_user_add_package.zip https://s3-us-west-2.amazonaws.com/mpower2-user-add/mpower2_user_add_package.zip --profile phil-admin
