from azure.botframework.connector import BotConnector
from azure.botframework.connectorauth import MicrosoftTokenAuthentication
from azure.botframework.connector import models
from datetime import datetime

MICROSOFT_APP_ID='39619a59-5a0c-4f9b-87c5-816c648ff357'
MICROSOFT_APP_PASSWORD='b90er1BC2xp9Y5Exqwj8qwf'

credentials = MicrosoftTokenAuthentication(MICROSOFT_APP_ID, MICROSOFT_APP_PASSWORD)
connector = BotConnector(credentials, base_url = 'https://facebook.botframework.com')

create_conversation = models.ConversationParameters()
create_conversation.is_group = False
bot = models.ChannelAccount()
bot.id = '726774820806739'
create_conversation.bot = bot
recipient = models.ChannelAccount()
recipient.id = '946773412111690'
create_conversation.members = [recipient]
activity = models.Activity()
activity.type = models.ActivityType.message
activity.channel_id = 'facebook'
activity.recipient = recipient
activity.text = 'Hi there!'
create_conversation.activity = activity

# create conversation
conversation = connector.conversations.create_conversation(create_conversation)

# send new activity to conversation
time_activity = models.Activity()
time_activity.type = models.ActivityType.message
time_activity.channel_id = 'facebook'
time_activity.recipient = recipient
time_activity.from_property = bot
time_activity.text = 'The current time is {:%H:%M}'.format(datetime.now())

response = connector.conversations.send_to_conversation(conversation.id, time_activity)