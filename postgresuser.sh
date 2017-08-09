su -c "createuser -DRS --password catalog" postgres
su -c "createdb -O catalog catalog" postgres
