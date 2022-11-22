#########################################################
# Cyber ML Capstone Project - Justin
# HarvardX Data Science Professional Certificate PH125.9x
# End Date: 
#########################################################

################################################################################
# 1. INTRODUCTION
################################################################################

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


# Finding the functions in which the packages listed are used. Please ignore the absolute path featured as it is used for my own reference.

used.functions <- NCmisc::list.functions.in.file(filename = "C:/Users/124Oh/Downloads/JOCyberMLFinal.R", alphabetic = FALSE) |> print()


# Finding what packages are unused entirely

used.packages <- used.functions |> names() |> grep(pattern = "packages:", value = TRUE) |> gsub(pattern = "package:", replacement = "") |> print()

unused.packages <- packageload[!(packageload %in% used.packages)] |> print()


######################################
# Creating the Train and Test Datasets
######################################

# The necessary dataset is able through my Github repository if the following code fails
download.file("https://raw.githubusercontent.com/justin-2028/Justin-2028-HarvardX-Capstone-Personal-Project/main/kaggleRCdataset.csv", "kaggleRCdataset.csv")
train = read.csv("kaggleRCdataset.csv", header = TRUE)
train.subset <- train[c('URL_LENGTH','NUMBER_SPECIAL_CHARACTERS','TCP_CONVERSATION_EXCHANGE','DIST_REMOTE_TCP_PORT','REMOTE_IPS','APP_BYTES','SOURCE_APP_PACKETS','REMOTE_APP_PACKETS', 'Type')]

# MinMax normalization to reduce biases when modeling through KNN and Random Forest 
minMax <- function(x) {
  return ((x - min(x)) / (max(x) - min(x))) }

train.subset.n <- as.data.frame(lapply(train.subset, minMax))
head(train.subset.n)

set.seed(123)
test_index <- sample(1:nrow(train.subset.n),size=nrow(train.subset.n)*0.2,replace = FALSE) #random selection of 20% data.

test.data <- train.subset[test_index,] # 20% will be test data
train.data <- train.subset[-test_index,] # remaining 80% will be training data

#Creating seperate dataframe for 'Type' feature which is our target.
test.data_labels <-train.subset[test_index,9]
train.data_labels <- train.subset[-test_index,9]

#Confirming whether the dataframe was created properly
#view(train.data_labels)
#view(test.data_labels)

################################################################################
# 2. METHODS AND ANALYSIS
################################################################################

######################################
# Data Exploration
######################################

# TYPE: this is a categorical variable, its values represent the type of web page analyzed, specifically, 1 is for malicious websites and 0 is for benign websites

# Lists amount of observations and variables in training data set "train"
dim(train)

# Displays column headers and first 10 rows as well as the last 10 rows
head(train, 10)
tail(train, 10)

# Shows the structure of the R object and other details
str(train)

#Displays column and row names for further clarity
colnames(train)
rownames(train)

# Used instead of summary(train) due to ___
describe(train)

# Checks for any missing (NA) values in the dataset
sum(is.na(train))

# Since there are a substantial amount of NA values, we will use colSums to see which columns contain the majority of the NA values.
colSums(is.na(train))

######################################
# Data Cleaning
######################################


######################################
# Modeling with KNN and Random Forest
######################################

#
# KNN
#

#Find the number of observation
NROW(train.data_labels) 

# Number of observations: 1425
# The root of 1425 is approximately 37.75, so two KNN models will be made with 37 and 38.

knn.37 <- knn(train=train.data, test=test.data, cl=train.data_labels, k=37)
knn.38 <- knn(train=train.data, test=test.data, cl=train.data_labels, k=38)

# Calculate the proportion of correct classification for k = 26, 27
accuracy.37 <- 100 * sum(test.data_labels == knn.37)/NROW(test.data_labels)
accuracy.38 <- 100 * sum(test.data_labels == knn.38)/NROW(test.data_labels)

accuracy.37

accuracy.38

# Check prediction against actual value in tabular form for k=37
table(knn.37,test.data_labels)

# Check prediction against actual value in tabular form for k=38
table(knn.38,test.data_labels)

confusionMatrix(table(knn.37,test.data_labels))
confusionMatrix(table(knn.38,test.data_labels))

i=1                          # declaration to initiate for loop
k.optm=1                     # declaration to initiate for loop
for (i in 1:100){ 
  knn.mod <-  knn(train=train.data, test=test.data, cl=train.data_labels, k=i)
  k.optm[i] <- 100 * sum(test.data_labels == knn.mod)/NROW(test.data_labels)
  k=i  
  cat(k,'=',k.optm[i],'\n')       # to print % accuracy 
}

plot(k.optm, type="b", xlab="K- Value",ylab="Accuracy level")


knn.8 <- knn(train=train.data, test=test.data, cl=train.data_labels, k=8)
accuracy.8 <- 100 * sum(test.data_labels == knn.8)/NROW(test.data_labels)
             
accuracy.8

#
# Random Forest
#

train.data$Type <- as.factor(train.data$Type)
modelrf <- randomForest(Type ~ ., data=train.data,ntree=1000)
(varimp.modelrf <- varImp(modelrf))

test.data$rf.pred <- predict(modelrf, newdata = test.data)
head(test.data[c("Type","rf.pred")], n=10)

(cm1 <- with(test.data,table(rf.pred,Type)))

################################################################################
# 3. RESULTS
################################################################################

################################################################################
# 4. CONCLUSION
################################################################################
