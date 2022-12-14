#########################################################
# Cyber ML Capstone Project - Justin Oh
# HarvardX Data Science Professional Certificate PH125.9x
# End Date: 11/22/22
#########################################################

######################################
# Preparing for the Dataset
######################################

# Required packages will install, please allow several minutes to complete.

if(!require(tidyverse)) install.packages("tidyverse", repos = "http://cran.us.r-project.org")
if(!require(purrr)) install.packages("purrr", repos = "http://cran.us.r-project.org")
if(!require(caret)) install.packages("caret", repos = "http://cran.us.r-project.org")
if(!require(Hmisc)) install.packages("Hmisc", repos = "http://cran.us.r-project.org")
if(!require(forecast)) install.packages("forecast", repos = "http://cran.us.r-project.org")
if(!require(randomForest)) install.packages("randomForest", repos = "http://cran.us.r-project.org")
if(!require(class)) install.packages("class", repos = "http://cran.us.r-project.org")
if(!require(data.table)) install.packages("data.table", repos = "http://cran.us.r-project.org")
if(!require(psych)) install.packages("psych", repos = "http://cran.us.r-project.org")
if(!require(readr)) install.packages("readr", repos = "http://cran.us.r-project.org")
if(!require(dplyr)) install.packages("dplyr", repos = "http://cran.us.r-project.org")
if(!require(NCmisc)) install.packages("NCmisc", repos = "http://cran.us.r-project.org")

# Packages for graphing and modeling
library(tidyverse)
library(purrr)
library(caret)
library(Hmisc)
library(forecast)
library(randomForest)
library(class)
library(data.table)
# Packages for reading the CSV file:
library(psych)
library(readr)
library(dplyr)
#Packages for testing what packages are used:
library(NCmisc)


# Loading packages listed:

packageload <- c("tidyverse", "caret", "data.table", "psych", "readr", "dplyr")
lapply(packageload, library, character.only = TRUE)


# Finding the functions in which the packages listed are used. Please ignore the absolute path featured as this code is used only for my own reference.

# used.functions <- NCmisc::list.functions.in.file(filename = "C:/Users/124Oh/Downloads/JOCyberMLFinal.R", alphabetic = FALSE) |> print()

# Finding what packages are unused entirely.

# used.packages <- used.functions |> names() |> grep(pattern = "packages:", value = TRUE) |> gsub(pattern = "package:", replacement = "") |> print()
# unused.packages <- packageload[!(packageload %in% used.packages)] |> print()


######################################
# Loading the Dataset
######################################

# The necessary dataset is able through my GitHub repository if the following code fails.
download.file("https://raw.githubusercontent.com/justin-2028/Justin-2028-HarvardX-Capstone-Personal-Project/main/kaggleRCdataset.csv", "kaggleRCdataset.csv")
train = read.csv("kaggleRCdataset.csv", header = TRUE)


######################################
# Data Cleaning
######################################

# Analyzing the WHOIS_COUNTRY variable for potential issues.
unique(train$WHOIS_COUNTRY)

# We can see that WHOIS_COUNTRY has different values for one country and that has to be corrected. For example: UK is shown as United Kingdom and GB. We need to correct that before moving forward.


train$WHOIS_COUNTRY <- as.character(train$WHOIS_COUNTRY)
train[train$WHOIS_COUNTRY == 'United Kingdom','WHOIS_COUNTRY'] <- "UK"
train[train$WHOIS_COUNTRY == "[u'GB'; u'UK']",'WHOIS_COUNTRY'] <- "UK"
train[train$WHOIS_COUNTRY == "GB",'WHOIS_COUNTRY'] <- "UK"
train[train$WHOIS_COUNTRY == "us",'WHOIS_COUNTRY'] <- "US"
train[train$WHOIS_COUNTRY == 'ru','WHOIS_COUNTRY'] <- "RU"

# Most countries don't seem to have any malicious data 
# This didn't seem to improve classification but might help performance by reducing dimensionality
# This could be overfitting/leakage but fine for current purposes
# W/ no validation or test sets that shouldn't matter much

mc <- train[train$Type == 1,'WHOIS_COUNTRY']
others <- which(!(train$WHOIS_COUNTRY %in% mc))
train[others,'WHOIS_COUNTRY'] <- "Other"
train$WHOIS_COUNTRY <- as.factor(train$WHOIS_COUNTRY)

# Now let's look at the values in CHARSET variable: 
unique(train$CHARSET)

# There is a similar problem in this variable as we saw in the WHOIS_COUNTRY variable: 
train$CHARSET <- as.character(train$CHARSET)
train[train$CHARSET == 'iso-8859-1',"CHARSET"] <- "ISO-8859-1"
train[train$CHARSET == 'utf-8',"CHARSET"] <- "UTF-8"
train[train$CHARSET == 'windows-1251',"CHARSET"] <- "windows-12##"
train[train$CHARSET == 'windows-1252',"CHARSET"] <- "windows-12##"
train$CHARSET <- as.factor(train$CHARSET)

# For the normalization of the SERVER variable, we will assign the values which do not have any malicious value in the data to the "Other" server value.

train$SERVER <- as.character(train$SERVER)
mserver <- train[train$Type == 1,"SERVER"]
others <- which(!(train$SERVER %in% mserver))
train[others,'SERVER'] <- "Other"
table(train$SERVER == "Other")
train$SERVER <- as.factor(train$SERVER)


# For the variables with NA values, we'll impute different values. 
colSums(is.na(train))

# Resolving two columns through imputation.
train$DNS_QUERY_TIMES=impute(train$DNS_QUERY_TIMES, 0)
train$CONTENT_LENGTH=impute(train$CONTENT_LENGTH, mean)

# Removing variables that will not be useful in the modelling process.
train$URL <- NULL
train$WHOIS_REGDATE <- NULL
train$CONTENT_LENGTH <- NULL

train$type<- as.factor(train$Type)

######################################
# Data Exploration
######################################

# TYPE: This is a categorical variable, and its values represent the type of web page analyzed, specifically, 1 is for malicious websites and 0 is for benign websites.

# Lists amount of observations and variables in training data set "train".
dim(train)

# Displays column headers and the first 10 rows as well as the last 10 rows.
head(train, 10)
tail(train, 10)

# Shows the structure of the R object and other details.
str(train)

# Used instead of summary(train) due to its provision of extra statistical details such as mean, median and variance.
describe(train)

# Let's plot DNS_QUERY_TIMES with target variables. 
ggplot(train, aes(x=as.factor(Type), y=DNS_QUERY_TIMES, fill=as.factor(Type))) + 
  geom_boxplot() +
  theme(legend.position="none")+
  ggtitle("Boxplot of Type by DNS_QUERY_TIMES")+
  theme(plot.title = element_text(hjust = 0.5))


# By the looks of it, DNS_QUERY_TIMES can be a good predictor. 

train%>%ggplot(aes(x=as.factor(Type), y=APP_PACKETS, fill=as.factor(Type))) + 
  geom_boxplot() +
  theme(legend.position="none")+
  ggtitle("Boxplot of Type by App Packets")+
  xlab('Type')+ylab('App Packets')+
  theme(plot.title = element_text(hjust = 0.5))
# There are a lot of outliers in this variable and there seems to be no difference between malicious and benign URLs for the APP_PACKETS variable. Our model will explain if this variable has potential to be a good predictor.

train%>%ggplot(aes(x=as.factor(Type), y=TCP_CONVERSATION_EXCHANGE, fill=as.factor(Type))) + 
  geom_boxplot() +
  theme(legend.position="none")+
  ggtitle("Boxplot of Type by TCP Conversation Exchange")+
  xlab('Type')+ylab('TCP Conversation Exchange')+
  theme(plot.title = element_text(hjust = 0.5))

# Examining the REMOTE_IPS variable:
train%>%ggplot(aes(x=as.factor(Type), y=REMOTE_IPS, fill=as.factor(Type))) + 
  geom_boxplot() +
  theme(legend.position="none")+
  ggtitle("Boxplot of Type by Remote IPS")+
  xlab('Type')+ylab('Remote IPS')+
  theme(plot.title = element_text(hjust = 0.5))

# Determining if URL_LENGTH is a good predictor for the type of URL link. 
train%>%ggplot(aes(x=as.factor(Type), y=URL_LENGTH, fill=as.factor(Type))) + 
  geom_boxplot() +
  theme(legend.position="none")+
  ggtitle("Boxplot of Type by URL Length")+
  xlab('Type')+ylab('URL Length')+
  theme(plot.title = element_text(hjust = 0.5))

# Plotting the distribution of all the numeric variables in the data to examine patterns.
train %>%
  keep(is.numeric) %>% 
  gather() %>% 
  ggplot(aes(value)) +
  facet_wrap(~ key, scales = "free") +
  geom_histogram()

######################################
# Creating the training and test datasets
######################################

# Implementing min-max normalization on the data.
minMax <- function(x) {
  return ((x - min(x)) / (max(x) - min(x))) }

train.subset <- train[c('URL_LENGTH','NUMBER_SPECIAL_CHARACTERS','TCP_CONVERSATION_EXCHANGE','DIST_REMOTE_TCP_PORT','REMOTE_IPS','APP_BYTES','SOURCE_APP_PACKETS','REMOTE_APP_PACKETS', 'Type')]

# Creating the training and test datasets, with 80-20 split.
train.subset.n <- as.data.frame(lapply(train.subset, minMax))
head(train.subset.n)

set.seed(123)
test_index <- sample(1:nrow(train.subset.n),size=nrow(train.subset.n)*0.2,replace = FALSE) #random selection of 20% data.

test.data <- train.subset[test_index,] # 20% will be test data
train.data <- train.subset[-test_index,] # remaining 80% will be training data

#Creating seperate dataframe for the 'Type' feature which is our target.
test.data_labels <-train.subset[test_index,9]
train.data_labels <- train.subset[-test_index,9]

#Confirming whether the dataframe was created properly.
#view(train.data_labels)
#view(test.data_labels)

######################################
# Modeling
######################################

# 
# Logistic Regression
# 

glm_model <- glm(Type~.,data = train.data)

#Looking at the summary of the model
summary(glm_model)

# We can see that all of the variables in the model are significant explainers of the Type variable. 

predictions<- as.factor(ifelse(predict(glm_model, newdata = test.data,type = 'response')>0.5,1,0))

confusionMatrix(predictions,as.factor(test.data_labels))

#
# KNN
#

# Running loop for KNN from 1 to 100 to test for a value of K that gives highest accuracy.

i=1                          # declaration to initiate for loop
k.optm=1                     # declaration to initiate for loop
for (i in 1:100){ 
  knn.mod <-  knn(train=train.data, test=test.data, cl=train.data_labels, k=i)
  k.optm[i] <- 100 * sum(test.data_labels == knn.mod)/NROW(test.data_labels)
  k=i  
  cat(k,'=',k.optm[i],'\n')       # to print % accuracy 
}

# Plots accuracy against value of K.
plot(k.optm, type="b", xlab="K- Value",ylab="Accuracy level")

# Fitting the KNN model for the value of K = 17.
knn.17 <- knn(train=train.data, test=test.data, cl=train.data_labels, k=17)
confusionMatrix(knn.17, as.factor(test.data_labels))

#
# Random Forest
#

# Fitting the model and checking the variable importance.
train.data$Type <- as.factor(train.data$Type)
modelrf <- randomForest(Type ~ ., data=train.data,ntree=1000)
(varimp.modelrf <- varImp(modelrf))

# Testing the output of above into the test dataset.
test.data$rf.pred <- predict(modelrf, newdata = test.data)
head(test.data[c("Type","rf.pred")], n=10)
confusionMatrix(as.factor(test.data$Type),as.factor(test.data$rf.pred))
