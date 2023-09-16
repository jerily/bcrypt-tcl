package require bcrypt

set salt [::bcrypt::gensalt 15]
puts salt=$salt
set hash [::bcrypt::hashpw "password" $salt]
puts hash=$hash
set match_correct_pw [::bcrypt::checkpw "password" $hash]
puts match_correct_pw=$match_correct_pw
set match_incorrect_pw [::bcrypt::checkpw "hello world" $hash]
puts match_incorrect_pw=$match_incorrect_pw

