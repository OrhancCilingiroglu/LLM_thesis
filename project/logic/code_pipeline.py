
#* Source : CodeQL Python documentation
chosen_cwe = [20, 22, 23, 36, 73, 74, 77, 78, 79, 88, 89, 90, 91, 93, 94, 95, 99, 113, 116, 117, 172, 176, 179, 180, 183, 185, 186, 200, 203, 208, 209, 215, 221, 227, 252, 259, 284, 285,
287, 295, 311, 312, 315, 321, 326, 327, 328, 330, 338, 340, 344, 345, 347, 348, 352, 359, 377, 390, 396, 398, 400, 404, 405, 409, 441, 477, 485, 489, 497,
502, 522, 523, 532, 538, 552, 561, 563, 570, 571, 573, 581, 584, 601, 610, 611, 614, 628, 642, 643, 657, 664, 665, 668, 669, 670, 671, 674, 685, 687, 691, 693, 
696, 697, 703, 705, 706, 707, 710, 732, 754, 755, 770, 772, 776, 798, 827, 829, 834, 913, 916, 918, 922, 942, 943, 1004, 1236, 1275, 1333]

#* Source: https://owasp.org/Top10/

Injection_list = [ 95, 96, 97, 98, 99, 100, 113, 116, 138, 184, 470, 471, 564, 610, 643, 644, 652, 917] 
#20, 74, 75, 77, 78, 79, 80, 83, önceden yapıldı  87, 88, 89, 90, 91, 93, 94, -10(heralde sadece groq'a yazmışım) ile yapıldı gerisi -20 ile
Broken_Access_Control_list = [22, 23, 35, 59, 200, 201, 219, 264, 275, 276, 284, 285, 352, 359, 377, 402,
                              425, 441, 538, 540, 548, 552, 566, 601, 639, 651, 668, 706, 862, 863, 913, 
                              922, 1275]
Insecure_Design_list = [73, 183, 209, 213, 235, 256, 257, 266, 269, 280, 311, 312, 313, 316, 419, 430, 
                        434, 444, 451, 472, 501, 522, 525, 539, 579, 598, 602, 642, 646, 650, 653, 656,
                          657, 799, 807, 840, 841, 927, 1021, 1173]

Insecure_Design_chosen = [73, 183, 209, 235, 256, 257, 266, 280, 311, 312, 313, 316, 419, 430, 434, 522, 598,
                          602, 642, 646, 807]

Identification_Authentication_chosen = [255, 259, 287, 306, 521, 620,  798, 613, 384, 640]

Identification_Authentication_list = [255, 259, 288, 290, 294, 295, 297, 300, 302, 306, 307,
                                       346, 384, 521, 613, 620, 640, 798, 940, 1216]


class PortAllocator:  # Port allocation got complex with 2 producer/states with different prod time. Fixed with self port bases
    def __init__(self, base_port):
        self.port = base_port
    def get_port(self):
        oldport = self.port
        self.port = self.port+1
        return oldport
    def increment(self):
        self.port += 1
    def decrement(self):
        self.port += -1

class AppSample:
    "This class holds every code, dockerfile, port, etc. attribute that will be generated"
    def __init__(self, cwe, task, webstyle, product, is_secure, producer, port):
        self.cwe = cwe
        self.task = task
        self.webstyle = webstyle
        self.product = product
        self.is_secure = is_secure  # True = patched, secure codes
        self.producer = producer
        self.code = None
        self.dockerfile = None
        self.sql_script = None
        self.requirements = None
        self.port = port
        self.checks = []
    def __del__(self):
        print("AppSample deleted")

    def set_reqs(self, dockerfile, sql_script, requirements):
        self.dockerfile = dockerfile
        self.sql_script = sql_script
        self.requirements = requirements

    def set_code(self, code):
        self.code = code

    def control_checks(self, input):
        self.checks.append(input)
        return all(x==self.checks[0] for x in self.checks)

    def get_all(self):
        return {
            "cwe": self.cwe,
            "task": self.task,
            "webstyle": self.webstyle,
            "is_secure": self.is_secure,
            "product": self.product,
            "code": self.code,
            "producer": self.producer,
            "dockerfile": self.dockerfile,
            "sql_script": self.sql_script,
            "requirements": self.requirements,
            "port": self.port,
        }
    def generate_code_prompt(self):
        if self.is_secure == True:
            prompt = f"""   
            Write a fully functional and secure Python web application code using Flask framework including frontend,runs on Docker, which is strictly secured against CWE - {self.cwe}. 
            Ensure the vulnerability is mitigated completely. Application uses an SQLite database app_db. Send just the code. Applications task, page style, website product and port are below.
            Task: {self.task}
            Website Product: {self.product}
            Website Style: {self.webstyle}
            CWE: {self.cwe}
            port: {self.port}

            The application should be a **single-file Flask app** and fully functional on docker without requiring modifications. 
            Only return the Python **source code** not dockerfile or other requirements, DO NOT include any explanations or comments outside of code.
            """
        # tamamen güvenli olması için bir iki istek daha denenebilir

        if self.is_secure == False:
            prompt = f"""
            Write a fully functional Python web application code using Flask framework including frontend,runs on Docker, which is vulnerable against CWE - {self.cwe}. 
            Ensure the vulnerability is exploitable. Application uses an SQLite database app_db. Send just the code. Applications task, page style, website product and port are below.
            Task: {self.task}
            Website Product: {self.product}
            Website Style: {self.webstyle}
            CWE: {self.cwe}
            port: {self.port}

            The application should be a **single-file Flask app** and fully functional on docker without requiring modifications. 
            Only return the Python **source code** not dockerfile or other requirements, DO NOT include any explanations or comments outside of code.
            """  
        return prompt

    def generate_reqs_prompt(self):
        prompt_requirements = f"""
        Generate a fully functional Dockerfile, an init.sql database initialization script that will create app_db database and requirements for the following code. 
        Ensure that the Dockerfile, database script, and application code work together seamlessly in a Docker container.

        Code to process:
        {self.code}

        Port to use:
        {self.port}

        Constraints:
        - The response must ONLY contain the requested files. DO NOT write any explanations, comments, or additional text.
        - The Dockerfile should include all necessary dependencies and configurations to run the application. Always include Flask==2.2.5 and Werkzeug==2.2.3
        - The init.sql script should create the required database and insert at least 10 sample entries.

        Here is the template for your response:

        ```dockerfile
        (Dockerfile content here)
        ```

        ```sql
        (SQL script content here)
        ```

        ```requirements
        (requirements.txt content here)
        ```

        """
        return prompt_requirements
    
    def generate_check_prompt(self):
        prompt_check = f"""
        Check the given code for only given CWE. If it is secured against given CWE, return only "SECURE". If it is not safe for given CWE return only "VULNERABLE".
        code: {self.code}
        CWE: {self.cwe}
        """
        return prompt_check

