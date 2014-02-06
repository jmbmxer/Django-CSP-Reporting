
from security_report.models import *
from django.utils import simplejson
from django.http import HttpResponse, HttpRequest
from django.views.decorators.csrf import csrf_exempt, csrf_protect
from django.views.generic import ListView, list_detail
import json

@csrf_exempt
def secreport(request):

	if request.method == "POST":
		json_data = simplejson.loads(request.raw_post_data)

		data = json_data['csp-report']
		document_uri = data['document-uri']
		referrer = data['referrer']
		blocked_uri = data['blocked-uri']
		violated_directive = data['violated-directive']
		source_file = data['source-file']
		script_sample = data['script-sample']

		b = security_report(csp_report = data, document_uri = document_uri, referrer = referrer,
		blocked_uri=blocked_uri, violated_directive = violated_directive, source_file=source_file, script_sample=script_sample)

		b.save()

		return HttpResponse("saved")


	else:
		b = security_report.objects.all()

		return HttpResponse("not a post request")


"""def ReportView(request):
    template_name = 'security_report_list.html'
    model = security_report"""




