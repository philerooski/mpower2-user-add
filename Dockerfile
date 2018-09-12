FROM philsnyder/synapse-notebook

RUN git clone https://github.com/philerooski/mpower2-user-add.git /root/mpower2-user-add

CMD /root/mpower2-user-add/user_add.py
