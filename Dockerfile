FROM amancevice/pandas:0.23.4-python3

RUN pip install synapseclient boto3 git+https://github.com/larssono/bridgeclient.git
#RUN git clone -b environment-variable-credentials https://github.com/philerooski/mpower2-user-add.git /root/mpower2-user-add
RUN git clone -b test-wrapper https://github.com/philerooski/mpower2-user-add.git /root/mpower2-user-add

CMD python /root/mpower2-user-add/user_add.py
