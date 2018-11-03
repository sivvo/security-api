#################################################
#
#  ARACHNI WEB VULNERABILITY SCANNER
#
#################################################

import datetime, json, simplejson
from flask import jsonify, request, abort, make_response, redirect, Blueprint, Response
from flask_restful import reqparse, abort, Api, Resource, fields
from flask_restful_swagger import swagger
from json import JSONEncoder
from flask.views import MethodView

from models import ArachniModel
import arachni, settings

arachniapi = Blueprint('arachniapi', __name__)
arachni = arachni.Arachni()


###################################
# Vulnerability Scanner
##################################
arachni_resource = swagger.docs(Api(arachniapi),
                        apiVersion='0.1',
                        basePath='https://127.0.0.1:8080',
                        resourcePath='/',
                        produces=["application/json", "text/html"],
                        api_spec_url='/spec',
                        description='Vulnerability scanner: Security tool')
###################################


class ARACHNIscan(Resource):
	

	def get(self):
		#abort_if_todo_doesnt_exist(scan_id)
		return TODOS, 200, {'Access-Control-Allow-Origin': '*'}

	@swagger.operation(
	notes='Perform arachni scan',
	nickname='get',
	parameters=[
	{
		"name": "body",
		"description": "Web Vulnerability scanner",
		"required": True,
		"allowMultiple": False,
		"dataType": ArachniModel.__name__,
		"paramType": "body"
	}
	],
	responseMessages=[
	{
		"code": 201,
		"message": "the arachni scan has been performed"
	},
	{
		"code": 405,
		"message": "Invalid input"
		},	
	{
		"code": 400,
		"message": "The browser (or proxy) sent a request that this server could not understand."
	}
	])
	def post(self):
		
		result=''	
		if not request.json or not 'scan_url' in request.json or not 'description' in request.json:
				abort(400)
		error = None
		url = ''

		#apilogger.info("Posting a new scan schedule")
		# TODO handle these mandatory paramaters

		scan_url = request.json['scan_url']
		report_suffix = datetime.datetime.now().strftime("%y%m%d_%H%M%S")
		#report_base = "/".join([self.config_class.report_dest_path,scan_url[7:]])
		report_base = scan_url[7:]
		report_dest = "_".join([report_base, report_suffix])

		try:
			scan = {
				'scan_url': request.json['scan_url'],
				'description': request.json['description'],
				'cookie string': request.json['cookie_string'],
				'request header': request.json['request_header'],
				'redirect limit': request.json['redirect_limit'],
				'unique id': settings.get_uuid(),
				'requestor': request.remote_addr,
				'report destination': report_dest
			}
		except:
			scan = {
				'scan_url': request.json['scan_url'],
				'description': request.json['description'],
				'cookie string': '',
				'request header': '',
				'redirect limit': 10,
				'unique id': settings.get_uuid(),
				'requestor': request.remote_addr,
				'report destination': report_dest
			}


		# TODO validate the config
		if not settings.is_valid_url(scan_url):
			error = 'Please enter a valid URL'
			print(error)

		else:
			result = arachni.save_scan( scan)
			exception_found = result[1]
			if exception_found == 1:
				# error occurred
				# TODO what's this gonna return...???

				return jsonify({'scan': scan})
			else:
				return redirect('/arachni/v1.0/scan/%s' % scan['unique id'], 302)
				
		return result, 200, {'Access-Control-Allow-Origin': '*'}

#################################################
#
# Arachni URLS
#
#################################################



#@app.route('/arachni/v1.0/help', methods=['GET'])
#def help():
#    return "arachni help\n"

#@app.route('/arachni/v1.0/scan/<scan_id>', methods=['GET'])
# single scan
#def get_report(scan_id):
#    query, exception = arachni.select_scan(scan_id)
#    if exception == 1 or len(query) == 0:
#        abort(404)
#    else:
#        print query
#        scan = [scan for scan in query ]
#        scan = [scan for scan in query if scan['id'] == scan_id]
#        return jsonify({'scan': scan[0]})

arachni_resource.add_resource(ARACHNIscan, '/v1.0/scan')
