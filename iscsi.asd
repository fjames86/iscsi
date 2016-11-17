;;;; Copyright (c) Frank James 2016 <frank.a.james@gmail.com>
;;;; This code is licensed under the MIT license.

(asdf:defsystem :iscsi
  :name "iscsi"
  :author "Frank James <frank.a.james@gmail.com>"
  :description "CFFI bindings to Windows iSCSI API" 
  :license "MIT"
  :serial t
  :components
  ((:file "iscsi"))
  :depends-on (:cffi))





