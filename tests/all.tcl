package require tcltest 2
if {[llength $argv]} {
    set library [file normalize [lindex $argv 0]]
    load $library Bcrypt
    set argv [lrange $argv 1 end]
    if {[file normalize [lindex [lindex [info loaded] end] 0]] ne $library} {error "loaded a different bcrypt library"}
} else {package require bcrypt 2.0.1}
::tcltest::configure -singleproc true -testdir [file dirname [info script]] {*}$argv
exit [::tcltest::runAllTests]
