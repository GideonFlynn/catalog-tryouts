#!/bin/bash
su -c "createuser -DRS catalog" postgres
su postgres bash -c "psql -c \"ALTER USER catalog WITH PASSWORD 'catalog';\""

# sudo nano /etc/apache2/sites-available/catalog.conf



#cd /var/www/flaskapps/catalog
#sudo pip install virtualenv
#sudo virtualenv venv
#source venv/bin/activate
#sudo pip install -r /var/www/flaskapps/catalog/requirements.txt
#deactivate
