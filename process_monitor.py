import psutil
import time
from datetime import datetime
alert_cooldowns = {}
COOLDOWN = 60

def should_alert(pid,alert_type):
    now = time.time()
    key = (pid,alert_type)
    if key not in alert_cooldowns or now - alert_cooldowns[key] >= COOLDOWN:
        alert_cooldowns[key] = now
        return True

    return False

try:
    while True:    
        for process in psutil.process_iter(['pid','name','username','status']):
            
            try:
                cpu = process.cpu_percent(interval=None)
                memory = process.memory_info().rss/ (1024*1024)

                if memory > 500 :
                                    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                                    alert = (
                                        f"[{timestamp}] Alert :  High Memory Usage | "
                                        f"Process : {process.info['name']} | "
                                        f"Memory Usage :{memory:.2f} MB | Severity : MEDIUM"
                                        )
                                    print(alert,flush=True)
                                    
                                    with open("security_events.log","a") as log_file:
                                        log_file.write(alert + "\n")

                print(f"Process ID : {process.info['pid']}")
                print(f"Process Name : {process.info['name']}")
                print(f"Username : {process.info['username']}")
                print(f"Status : {process.info['status']}")
                print(f"Memory :{memory:.2f} MB")
                print(f"CPU usage :{cpu:.2f}%")
                if cpu > 80 and should_alert(process.info['pid'],"cpu") :
                    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    print(
                        f"[{timestamp}] Alert :  High CPU Usage | "
                        f"Process : {process.info['name']} | "
                        f"CPU Usage :{cpu:.2f}% | Severity : MEDIUM\n")
                    
                    with open("security_events.log","a") as log_file:
                        log_file.write(
                            f"[{timestamp}] Alert :  High CPU Usage | "
                            f"Process : {process.info['name']} | "
                            f"CPU Usage :{cpu:.2f}% | Severity : MEDIUM\n")
                print("-" * 40)
        #         print(process.info)
            except psutil.AccessDenied:
                print("Access denied to process")  
            except psutil.NoSuchProcess:
                print("Process no longer exists")
            except psutil.ZombieProcess:
                print("Zombie process encountered")  

        time.sleep(3)

except KeyboardInterrupt:
    pass

    # print("Process monitoring stopped !!")

# cnt =0
# for process in psutil.process_iter():
    # print(process)
    # cnt+=1
    # if cnt ==10:
    #     break
# process= psutil.Process(1028)
# p= psutil.Process()
# print(p.memory_percent())