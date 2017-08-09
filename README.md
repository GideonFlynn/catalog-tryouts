# Is it Vegan - A FSND project
### This app categorizes items in danish. The requirements for an item to get displayed is being 100% vegan.
This is a flask web application, it uses OAuth2 providers to authenticate users and store them in a database.

The app has CRUD operations for:
- Categories
- Shops
- Manufacturers
- Items
  - To add a new category/shop/manufacturer go to 'http://localhost:5050/tablename/new'
    - For items, instead go to 'http://localhost:5050/category-id/item/new'
  - To edit an entry - provided you are the creator - go to the entry and press the edit button
  - To delete an entry - provided you are the creator - go to the entry and press the delete button

  ##### The app _needs_ an image when you add a new entry. The reason being the way entries get displayed.

# Requirements
A script is initialized when installing the virtual environment, which downloads the necessary software.
- Install Vagrant
- Install VirtualBox

# Installing
This code runs in a Vagrant environment:
- Download the ItemCatalog folder
- Navigate to the downloaded folder
- Open a terminal
  ###### Bash is nice, it comes with git.. which is also nice :)
- Run `vagrant init`
  ###### This might take a while, go grab some water or do some exercises
  ###### Congratulations! You are now able to access the vagrant folder inside your 'box'
  ## Running
  - `vagrant up`
  - `vagrant ssh`
    - `cd /vagrant`
  
  ###### An now for the exiting part, running the app!
    - Inside the vagrant folder: `python ItemCatalog.py`
#
#### This application is essentially a catalog of items where each item is connected to one category and references a shop id and a manufacturer id.

##### The database relationships could be represented like this:

###### _User |_

###### _Category -> [Item] |_

###### _Item -> [Shop, Manufacturer] |_

###### _Shop |_

###### _Manufacturer |_

If you search 'Column' in the dbmodels.py file, you'll easily be able to read which rows each table in the database has.


# API
Go to the [API docs](https://documenter.getpostman.com/view/2229326/item-catalog/6fSWmNf), they are generated with Postman.

An alternative is downloading [the Postman app](https://www.getpostman.com/) and pressing this button:
[![Run in Postman](https://run.pstmn.io/button.svg)](https://app.getpostman.com/run-collection/4263598c8bd1b5ce049e)


# Built with
- Python 2.7
- Vagrant
  ### Using
- Pycharm - Coding
- Postman - APIs
- Webflow - Looks*

  *I'm currently in the process of re-designing the front-end, ETA 01/08/17.

# Contribution
All contributions a greatly appreciated.
1. Fork it!
2. Create your feature branch: `git checkout -b my-new-feature`
3. Commit your changes: `git commit -am 'Add some feature'`
4. Push to the branch: `git push origin my-new-feature`
5. Submit a pull request :D

# Acknowledgements
Udacity's Full-Stack Nanodegree(FSND) is the reason this project exists. I cannot express how grateful I am for being able to follow this degree.

The Udacity forums is a great place to get ideas on how to solve hard problems given by the instructors.

The Udacity forums also provides a fantastic way to learn - by teaching others.

[ibrahimokdadov's YouTube channel](https://www.youtube.com/channel/UCA5BYnCVKNU2XhpDJO-1XgA), who made a great tutorial on storing images in Flask.

All the people who spend their time writing great documentation
and all of those amazing people answering questions on Stack Overflow and many other places on the internet. Without you, coding would be extremely exhausting.
