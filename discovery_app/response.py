from rest_framework import status
from rest_framework.response import Response


class TaskResponse(Response):
    def __init__(self, task, custom_data=None):
        task_response = {
            'task_id': task.task_id,
        }
        if custom_data:
            task_response.update(custom_data)
        super(TaskResponse, self).__init__(
            task_response,
            status=status.HTTP_202_ACCEPTED
        )
