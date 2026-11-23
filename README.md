# How an EDR watches the system: notes from reading OpenEDR

Notes I wrote while reading the source of Comodo OpenEDR, an open-source endpoint detection and response agent, to understand how it collects data, decides what looks malicious, and responds.

I come from the offensive side, mostly web and API testing. I read this to see the defensive mirror of the techniques I practice: when I run an attack, what does an EDR actually record, and which step gives me away.

## The two halves: kernel and user mode

Windows separates privileged code (kernel mode, ring 0) from normal programs (user mode). OpenEDR has a component in each, and the split is deliberate.

```
   kernel mode                          user mode
 +-------------------+   events       +---------------------+      +-----------+
 |  kernel driver    | ------------>  |  agent / service    | ---> |  console  |
 |  (the sensors)    |  via a comms   |  (correlation,      |      |  or SIEM  |
 |  kernel callbacks |  channel       |   detection logic)  |      +-----------+
 +-------------------+                +---------------------+
```

The driver sits in the kernel because that is where it can see process, thread, image, registry, and handle activity that user-mode malware tries to hide. The heavy analysis lives in user mode because a fault in kernel code is a bug check (the blue screen), so the kernel side stays small and careful and ships raw events upward.

## Kernel callbacks: the sensors

The driver does not hook the kernel by force. It registers callbacks, the documented way for a driver to be told when something happens, and the kernel calls them. These are the five I focused on:

| Callback | Windows API | What it reports | What it helps catch |
|---|---|---|---|
| Process creation | `PsSetCreateProcessNotifyRoutineEx` | process start and exit, parent, image path, command line | a document spawning a shell, suspicious parent and child pairs |
| Image load | `PsSetLoadImageNotifyRoutine` | a DLL, driver, or executable mapped into memory | DLL injection, loading an unsigned or unexpected driver |
| Thread creation | `PsSetCreateThreadNotifyRoutine` | thread start, including in another process | remote thread injection into a running process |
| Registry | `CmRegisterCallbackEx` | registry reads and writes | persistence via run keys, configuration tampering |
| Handle operations | `ObRegisterCallbacks` | a process opening a handle to another process or thread | credential access, for example a handle opened to `lsass.exe` |

Process creation is the backbone of the timeline, since almost every action starts a process. Handle operations are the one I watch most as an attacker, because reading `lsass` memory to pull credentials shows up right here.

## From kernel to user mode: why the heavy work happens up top

The driver collects raw events and passes them to the user-mode agent over a communication channel rather than deciding guilt in the kernel. The agent enriches each event, correlates it with the ones around it, applies detection logic, and forwards the result to a console or a SIEM. The kernel side collects, the user-mode side decides.

## Behaviour versus signature

Traditional antivirus matches a file against a database of known-bad hashes and byte patterns. It is fast and precise on known samples and blind to new or fileless ones, and repacking a file defeats it.

An EDR watches what a process does. "A process opened a handle to lsass and read its memory" is suspicious whatever the file is called, so the technique stays detectable even when the binary changes. This is the same idea behind MITRE ATT&CK: describe and detect the technique rather than the file.

## Mapping an attack to the telemetry it leaves

The reason this was worth my time, written as a small table from the attacker's side to the sensor that records it.

| Attacker action | Sensor that records it | MITRE technique |
|---|---|---|
| Office document launches PowerShell | process creation (parent and child) | T1059 |
| Inject a thread into another process | thread creation | T1055 |
| Load a malicious or unsigned driver | image load | T1014 / T1068 |
| Add a Run key for persistence | registry | T1547.001 |
| Open a handle to `lsass.exe` and read memory | handle operations | T1003.001 |

## What I took from this

Every offensive technique I use leaves a specific trace, and the trace is usually earlier and louder than I would like. Reading an EDR from the inside made my own attacks legible to me: I can now point at the exact event a defender would alert on, which is as useful for writing detections as it is for testing them.

---

Scope: this is a source review and architecture notes. It documents my understanding of a public open-source project and contains no proprietary or certification exam material. Windows API names reference Microsoft's public documentation.
