"use strict";
const AWS = require("aws-sdk");
const bcrypt = require("bcryptjs");
module.exports.createUser = async (event, context) => {
  const body = JSON.parse(event.body);
  const { username, password } = body;

  const newUserParams = {
    TableName: process.env.DYNAMODB_USER_TABLE,
    Item: {
      pk: username,
      password: bcrypt.hashSync(password, 10),
    },
  };
  try {
    const dynamodb = new AWS.DynamoDB.DocumentClient();
    const putResult = await dynamodb.put(newUserParams).promise();
    return {
      statusCode: 201,
      headers: {
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Credentials": true,
        "Access-Control-Allow-Headers": "Authorization",
      },
    };
  } catch (error) {
    console.log("There was an error putting the item");
    console.log("putError", error);
    console.log("newUserParams", newUserParams);
    return new Error("There was an error putting the item");
  }
};
