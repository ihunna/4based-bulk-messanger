# -*- coding: utf-8 -*-

from app_configs import creators_file,configs_folder,universal_files
from utils import Utils
from configs import *
import io


class Creator:
	def __init__(self):
		self.proxies = Utils.load_proxies()
		self.headers = {
			'authority': 'rest.4based.com',
			'accept': 'application/json',
			'accept-language': 'en-US,en;q=0.9',
			'content-type': 'application/json',
			'origin': 'https://4based.com',
			'referer': 'https://4based.com/',
			'sec-ch-ua': '"Not A(Brand";v="99", "Google Chrome";v="121", "Chromium";v="121"',
			'sec-ch-ua-mobile': '?1',
			'sec-ch-ua-platform': '"Android"',
			'sec-fetch-dest': 'empty',
			'sec-fetch-mode': 'cors',
			'sec-fetch-site': 'same-site'
		}

	def generate_sensor_data(self,type='x-auth-resource'):
		if type == 'x-auth-resource':
			return ''.join(random.choices(string.ascii_letters.upper() + string.digits + string.ascii_letters, k=len('2NTN5vEez9')))


	def scrape_users(self,session):
		try:
			params = {
				'offset': '0',
				'limit': '40',
				'search': 'a',
				'sort': '{"follower_count":"asc"}',
				# 'verified': 'true',
				'role': 'client',
			}

			response = session.get(
				'https://rest.4based.com/api/1.0/user', 
				params=params)
			
			if response.ok:
				users = response.json()

				valid_users = [user for user in users 
				   if not user.get('creator',False) 
				   and user.get('cold_communication_status') != 'actively_not_contactable']
				
				return True, valid_users

			else:
				return False, f'Error fetching users: {response.text}'

		except Exception as e:
			return False, str(e)

	def send_messages(self,admin,task_id,creator,config):
		try:
			success,task_status = Utils.check_task_status(task_id)
			if not success:raise Exception(task_status)
			if task_status['status'].lower() in ['cancelled','canceled']:return False,  'Task canceled'

			creator_name = user['details']['user']['name']
			email = user['details']['user']['identifier']
			user_id = user['details']['user']['_id']
			captions = config.get('captions',[])
			caption_source = config.get('caption_source','creator')
			has_media = config.get('has_media',False)
			media_id = config.get('media_id',None)
			is_paid = config.get('is_paid',False)
			price = config.get('price',0)

			success,user = self.login(
				admin=admin,
				email=creator['email'],
				user_name=creator['data']['details']['user']['name'],
				password=creator['password'],
				reuse_ip=creator.get('reuse_ip',True),
				task_id=task_id
			)
			if not success:raise Exception(user)
			
			if caption_source == 'creator':
				captions = str(random.choice(captions)).replace('\n','')

			else:
				captions_file = os.path.join(configs_folder,creator['id'],'captions.txt')
				if not isfile(captions_file):raise Exception(f'Captions file does not exist for {creator_name}')
				captions = []
				with open(captions_file,'r',encoding='utf-8') as f:
					captions = f.readlines()

			if (not 'headers' in user.keys() or len(user.get('headers',{})) < 1) or (not 'cookies' in user.keys() or len(user.get('cookies',{})) < 1):
				return False,f'User {creator_name} does not have session data'
			
			session = requests.Session()
			session.headers.update(user.get('headers'))
			session.cookies.update(user.get('cookies'))

			success, users = self.scrape_users(session)

			response = session.get(
				f'https://rest.4based.com/api/1.0/user/name/{user["name"]}',
				params=params,
				headers=self.headers,
				cookies=creator.get('cookies',{})
			)

			if response.status_code == 200:
				user['details'] = response.json()
			
			else:
				return False,f'Error fetching user details: {response.text}'

			messages = config.get('messages',[])
			if not messages or len(messages) < 1:return True,'No messages to send'

			for message in messages:
				json_data = {
					'text': message,
					'locale': 'en',
					'with_user_pivot_interaction': 'true',
					'with_user_pivot': 'true',
					'with_user_pivot_creator': 'true',
					'with_user_pivot_creator_interaction': 'true',
					'with_user_pivot_creator_details': 'true',
					'with_user_pivot_creator_details_interaction': 'true',
					'with_user_pivot_creator_details_interaction_details': 'true',
					'with_user_pivot_creator_details_interaction_details_media': 'true',
					'with_user_pivot_creator_details_interaction_details_media_files': 'true',
					'with_user_pivot_creator_details_interaction_details_media_files_images': 'true',
					'with_user_pivot_creator_details_interaction_details_media_files_videos': 'true'
				}

				response = session.post(
					f'https://rest.4based.com/api/1.0/user/{user_id}/message',
					headers=self.headers,
					json=json_data,
					cookies=creator.get('cookies',{})
				)

				if response.status_code == 200:
					success = True
					result = response.json()
				else:
					result = f'Error sending message: {response.text}'

			return success,result

		except Exception as e:
			return False,str(e)

	def login(self,admin,email,password,reuse_ip=True,task_id=None,category='creators'):
		try:
			success,result,user,new_user = False,'Login failed',{},True
			
			if task_id is not None:
				success,task_status = Utils.check_task_status(task_id)
				if not success:raise Exception(task_status)
				if task_status['status'].lower() in ['cancelled','canceled']:return False,  'Task canceled'
				

			success,user = Utils.check_creator(email,admin)
			if not success:raise Exception(user)

			creator_id = user.get('id',None)
			user = user.get('data',{})

			if len(user.items()) >= 1 and (user.get('cookies',False) and user.get('headers',False)):new_user = False

			if reuse_ip and 'proxies' in user.keys():
				proxies = user['proxies']
			else: proxies = random.choice(self.proxies)

			# check session
			if not new_user:
				params = {
					'with_user_pivot_interaction': 'true',
				}

				response = requests.get(
					f"https://rest.4based.com/api/1.0/user/name/{user['details']['user']['name']}",
					params=params,
					headers=user.get('headers',{}),
					cookies=user.get('cookies',{}),
					proxies=proxies
				)

				if response.status_code == 200:
					return True, user
				
			json_data = {
				'identifier': email,
				'password': password,
				'locale': 'en',
			}

			self.headers.update({
				'user-agent': Utils.generate_user_agent('android',1),
				'x-auth-resource': self.generate_sensor_data(),
			})
			
			session = requests.Session()
			session.headers.update(self.headers)
			session.proxies = proxies

			response = session.post(
				'https://rest.4based.com/api/1.0/auth/login',  
				json=json_data
			)

			if response.status_code == 400:
				if 'password not correct' in response.json().values():
					success,result = True,'password not correct'
			
			elif not response.ok:
				user['status'] = 'Offline'
				success,result = False,response.text

			else:
				data = response.json()
				token,auth_resource = data['details']['credentials']['token'],data['details']['credentials']['resource']

				user['status'] = 'Online'
				user['details'] = data
				user['details']['user']['password'] = password
				avatar = user['details']['user']['avatar']
				
				session.headers.update({
					'x-auth-resource': auth_resource,
					'x-auth-token':token
				})

				user['headers'] = session.headers
				user['cookies'] = session.cookies.get_dict()

				if avatar is not None:
					image_url = f'https://pic.4based.com/preview/{avatar["code"]}/{avatar["_id"]}/300x300.{avatar["extension"]}'
					user['details']['user']['picture'] = image_url

				user['proxies'] = proxies
				user['reuse_ip'] = reuse_ip

			if new_user:
				creator_id = str(uuid.uuid4()).upper()[:8]
				success,msg = Utils.add_creator(creator_id,email,user,admin,category=category,task_id=task_id)

				images_folder = os.path.join(configs_folder,creator_id,'images')
				videos_folder = os.path.join(configs_folder,creator_id,'videos')
				captions_file = os.path.join(configs_folder,creator_id,'captions.txt')
				
				os.makedirs(images_folder,exist_ok=True)
				os.makedirs(videos_folder,exist_ok=True)
				with open(captions_file, 'w') as file:file.write("")

			else:
				success,msg = Utils.update_creator(creator_id,email,user)
			if not success:raise Exception(msg)

			user['id'] = creator_id
			success,result = True,user
			return success,result
		
		except Exception as error:
			error = f'Error logging in {error} on {email}'
			Utils.write_log(error)
			return False,error
			
	def update(self,user:dict,data:dict):
		try:
			user_email,user_id,user = user['email'],user['id'],user['data']
			for key,value in data.items():
				user[key] = value
			success,msg = Utils.update_creator(user_id,user_email,user)
			if not success:raise Exception(msg)
			return True,user
		except Exception as error:
			return False, error
	

class _4BASED:

	def __init__(self):
		self.proxies = Utils.load_proxies()
		self.headers = {
			'authority': 'rest.4based.com',
			'accept': 'application/json',
			'accept-language': 'en-US,en;q=0.9',
			'content-type': 'application/json',
			'origin': 'https://4based.com',
			'referer': 'https://4based.com/',
			'sec-ch-ua': '"Not A(Brand";v="99", "Google Chrome";v="121", "Chromium";v="121"',
			'sec-ch-ua-mobile': '?1',
			'sec-ch-ua-platform': '"Android"',
			'sec-fetch-dest': 'empty',
			'sec-fetch-mode': 'cors',
			'sec-fetch-site': 'same-site'
		}


	def add_creators(self,admin,task,creators,category):
		task_status,task_msg,completed,fails = 'failed',f'Started logging in creators for {task["id"]}',0,0
		try:
			Utils.write_log(f'=== Add {category} started for {task["id"]} ===')
			task_id = task['id']

			with ThreadPoolExecutor(max_workers=10) as executor:
				args = [(
					admin,
					creator['email'],
					creator['password']
					) for creator in creators]
				kwargs = [{'task_id':task_id,'category':category} for creator in creators]
				
				futures = []
				for arg,kwarg in zip(args,kwargs):
					success,task_status = Utils.check_task_status(task_id)
					if not success:raise Exception(task_status)
					if task_status['status'].lower() in ['cancelled','canceled']:break

					future = executor.submit(Creator().login, *arg, **kwarg)
					futures.append(future)

				for future in as_completed(futures):
					success,task_status = Utils.check_task_status(task_id)
					if not success:raise Exception(task_status)
					
					if task_status['status'].lower() in ['cancelled','canceled']:
						for remaining_future in futures:
							remaining_future.cancel()
						break

					success,result = future.result()
					if success:
						completed += 1

						client_msg = {'msg':f'{completed} {category} added so far on task:{task_id}','status':'success','type':'message'}
						success,msg = Utils.update_client(client_msg)
						if not success:Utils.write_log(msg)


					elif not success and result == 'Task canceled':
						task_status = 'canceled'
						client_msg = {'msg':f'{result} task:{task_id}','status':'error','type':'message'}
						
						success,msg = Utils.update_client(client_msg)
						if not success:Utils.write_log(msg)
						break
					
					else:
						fails += 1
						client_msg = {'msg':f'{fails} creators added so far on task:{task_id}','status':'error','type':'message'}
						
						success,msg = Utils.update_client(client_msg)
						if not success:Utils.write_log(msg)
						task_msg = result

		except Exception as error:
			Utils.write_log(error)
			task_status = 'failed'
			task_msg = f'Error adding creators on {task_id} : {error}'

		finally:
			if task_status == 'canceled':
				client_msg = {'msg':f'{task_id} was canceled','status':'error','type':'message'}
				task_msg = client_msg['msg']

			elif completed == len(creators) and len(creators) > 0:
				task_status = 'success'
				client_msg = {'msg':f'{task_id} successful','status':'success','type':'message'}
				
			elif  fails > len(creators) // 2:
				client_msg = {'msg':f'{task_id} failed','status':'error','type':'message'}
				task_status = 'failed'
				task_msg = client_msg['msg']
			
			elif task_status == 'failed':
				client_msg = {'msg':f'{task_id} failed','status':'error','type':'message'}
			
			else:
				task_status = 'completed'
				client_msg = {'msg':f'{completed} items successful task:{task_id}','status':'success','type':'message'}
				task_msg = client_msg['msg']

			success,msg = Utils.update_client(client_msg)
			if not success:Utils.write_log(msg)

			success,msg = Utils.update_task(task_id,{
				'status':task_status,
				'message':task_msg
			})
			if not success:Utils.write_log(msg)
			
			task_data = task
			task_data.update(
				{'updated':str(datetime.now()),
				'status':task_status})

			success,msg = Utils.update_client({'task':task_data,'type':'task'})
			if not success:Utils.write_log(msg)


	def start_messaging(self,task):
		task_status,task_msg,completed,fails = 'failed',f'Started messaging for {task["id"]}',0,0
		try:

			admin = task['admin']
			task_id = task['id']
			config = task['config']
			selected_creators = config.get('select-creators',[])

			success,creators,total_creators = Utils.get_creators(admin=admin,limit=100,selected_creators=selected_creators)
			if not success:raise Exception(creators)
			
			len_creators = len(creators)
			if len_creators < total_creators:
				for i in range(total_creators - len_creators):
					offset = len_creators + i
					success,msg,total_creators = Utils.get_creators(admin=admin,limit=100,offset=offset,selected_creators=selected_creators)
					if not success:raise Exception(msg)
					creators += msg

			Utils.write_log(f'=== Messaging started for {task_id} ===')

			with ThreadPoolExecutor(max_workers=10) as executor:
				args = [(
					admin,
					task_id,
					creator,
					config
					) for creator in creators]
				
				futures = []
				for arg in args:
					success,task_status = Utils.check_task_status(task_id)
					if not success:raise Exception(task_status)
					if task_status['status'].lower() in ['cancelled','canceled']:break

					future = executor.submit(Creator().send_messages, *arg)
					futures.append(future)

				for future in as_completed(futures):
					success,task_status = Utils.check_task_status(task_id)
					if not success:raise Exception(task_status)
					
					if task_status['status'].lower() in ['cancelled','canceled']:
						for remaining_future in futures:
							remaining_future.cancel()
						break

					success,result = future.result()
					if success:
						completed += 1

						client_msg = {'msg':f'{completed} messages sent so far on task:{task_id}','status':'success','type':'message'}
						success,msg = Utils.update_client(client_msg)
						if not success:Utils.write_log(msg)


					elif not success and result == 'Task canceled':
						task_status = 'canceled'
						client_msg = {'msg':f'{result} task:{task_id}','status':'error','type':'message'}
						
						success,msg = Utils.update_client(client_msg)
						if not success:Utils.write_log(msg)
						break
					
					else:
						fails += 1
						client_msg = {'msg':f'{fails} creators messaged so far on task:{task_id}','status':'error','type':'message'}
						
						success,msg = Utils.update_client(client_msg)
						if not success:Utils.write_log(msg)
						task_msg = result

		except Exception as error:
			Utils.write_log(error)
			task_status = 'failed'
			task_msg = f'Error messaging creators on {task_id} : {error}'

		finally:
			if task_status == 'canceled':
				client_msg = {'msg':f'{task_id} was canceled','status':'error','type':'message'}
				task_msg = client_msg['msg']

			elif completed == len(creators) and len(creators) > 0:
				task_status = 'success'
				client_msg = {'msg':f'{task_id} successful','status':'success','type':'message'}
				
			elif  fails > len(creators) // 2:
				client_msg = {'msg':f'{task_id} failed','status':'error','type':'message'}
				task_status = 'failed'
				task_msg = client_msg['msg']
			
			elif task_status == 'failed':
				client_msg = {'msg':f'{task_id} failed','status':'error','type':'message'}
			
			else:
				task_status = 'completed'
				client_msg = {'msg':f'{completed} items successful task:{task_id}','status':'success','type':'message'}
				task_msg = client_msg['msg']

			success,msg = Utils.update_client(client_msg)
			if not success:Utils.write_log(msg)

			success,msg = Utils.update_task(task_id,{
				'status':task_status,
				'message':task_msg
			})
			if not success:Utils.write_log(msg)
			
			task_data = task
			task_data.update(
				{'updated':str(datetime.now()),
				'status':task_status})

			success,msg = Utils.update_client({'task':task_data,'type':'task'})
			if not success:Utils.write_log(msg)