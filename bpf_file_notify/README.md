# BPF File Notify

This project is meant to fulfill a few things in the CBC Event Pipeline,
and to not be part of the bpf event collector.

## BPF Based Static File Banning
This cab be used to ban files within BPF without requiring fanotify.
But can be extended to do many more things `fanotify` never can!

### Synchronizations with ILB
However if you do end still using ILB with fanotify, ensure you mark files as
ignore in your fanotify instance when you mark them for ban in BPF.


## File/Inode Type/Labeling and Caching
This could be extended to more than just banning, so file reputation, file digests,
lookups etc. Even as a tool to design creating new security access controls.



## Reasons To Use
 - Banning doesn't interupt userspace and is face
 - Banning decisions can optionally notify userspace
 - Provides extensive and complete form of file caching
 - Eventually add self protections
 - Extend to embed file reputation into kernel objects!
 - Could eventually be used to help filter out more events in sensor.bpf.c


## Reasons To Not Use
 - You don't like accurate file caching
 - You don't like fast and efficient file banning
 - You don't care about performance

