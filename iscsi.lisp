;;;; Copyright (c) Frank James 2016 <frank.a.james@gmail.com>
;;;; This code is licensed under the MIT license.

;;; This file defines CFFI wrappers to the API for the
;;; Microsoft iSCSI initiator.
;;; Not all the functions are wrapped and some things
;;; are missing notably some of the constants for flags.

(defpackage #:iscsi
  (:use #:cl #:cffi)
  (:export #:login-target
           #:logout-target
           #:list-initiators 
           #:initiator-node-name
           #:list-sessions
           #:add-send-target-portal
           #:remove-send-target-portal
           #:list-targets
           #:refresh-send-target-portal
           #:list-send-target-portals))
          
(in-package #:iscsi)

(define-foreign-library iscsidsc
  (t (:default "iscsidsc")))

(use-foreign-library iscsidsc)

;; -------------------- for errors ----------------------------

(defcfun (%format-message "FormatMessageA" :convention :stdcall)
    :uint32
  (flags :uint32)
  (source :pointer)
  (msg-id :uint32)
  (lang-id :uint32)
  (buffer :pointer)
  (size :uint32)
  (args :pointer))

(defun format-message (code)
  "Use FormatMessage to convert the error code into a system-defined string."
  (with-foreign-object (buffer :uint8 1024)
    (let ((n (%format-message #x00001000
			      (null-pointer)
			      code
			      0
			      buffer
			      1024
			      (null-pointer))))
      (if (= n 0)
	  (error "Failed to format message")
	  (foreign-string-to-lisp buffer
				  :count (- n 2))))))

(define-condition win-error (error)
  ((code :initform 0 :initarg :code :reader win-error-code))
  (:report (lambda (condition stream)
	     (format stream "ERROR ~A: ~A" 
		     (win-error-code condition)
		     (format-message (win-error-code condition))))))

(defcfun (%get-last-error "GetLastError" :convention :stdcall) :long)

(defun get-last-error (&optional code)
  (let ((%code (or code (%get-last-error))))
    (unless (zerop %code)
      (error 'win-error :code %code))))


(defun iscsi-error-p (code)
  (let ((hi (logand #xffff0000 code)))
    (or (= hi #xefff0000)
        (= hi #xafff0000))))

(defparameter *iscsi-errors*
  '(("Non-specific error" #xefff0001)
    ("Login failed" #xefff0002)
    ("Connection failed" #xefff0003)
    ("Node already exists" #xefff0004)
    ("Node not found" #xefff0005)
    ("Target moved temporarily" #xefff0006)
    ("Target moved permanently" #xefff0007)
    ("Initiator error" #xefff0008)
    ("Authentication failure" #xefff0009)
    ("Authorization failure" #xefff000a)
    ("Not found" #xefff000b)
    ("Target removed" #xefff000c)
    ("Unsupported version" #xefff000d)
    ("Too many connections" #xefff000e)
    ("Missing parameter" #xefff000f)
    ("Can't include in session" #xefff0010)
    ("Session type not supported" #xefff0011)
    ("Target error" #xefff0012)
    ("Service unavailable" #xefff0013)
    ("Out of resources" #xefff0014)
    ("Connection already exists" #xefff0015)
    ("Session already exists" #xefff0016)
    ("Initiator instance not found" #xefff0017)
    ("Target already exists" #xefff0018)
    ("Driver bug" #xefff0019)
    ("Invalid text key" #xefff001a)
    ("Invalid sendtargets text" #xefff001b)
    ("Invalid session ID" #xefff001c)
    ("SCSI request failed" #xefff001d)
    ("Too many sessions" #xefff001e)
    ("Session busy" #xefff001f)
    ("Target mapping unavailable" #xefff0020)
    ("Address type not supported" #xefff0021)
    ("Login failed" #xefff0022)
    ("Send failed" #xefff0023)
    ("Transport error" #xefff0024)
    ("Version mismatch" #xefff0025)
    ("Target mapping out of range" #xefff0026)
    ("Target preshared key unavailable" #xefff0027)
    ("Target auth info unavailable" #xefff0028)
    ("Target not found" #xefff0029)
    ("Login user info bad" #xefff002a)
    ("Target mapping exists" #xefff002b)
    ("HBA Security cache full" #xefff002c)
    ("Invalid port number" #xefff002d)
    ("Operation not all success" #xafff002e) ;; #xefff002e ???
    ("HBA security cache not supported" #xefff002f)
    ("IKE ID Payload type not supported" #xefff0030)
    ("IKE ID payload incorrect size" #xefff0031)
    ("Target portal already exists" #xefff0032)
    ("Target address already exists" #xefff0033)
    ("No auth info available" #xefff0034)
    ("No tunnel outer mode address" #xefff0035)
    ("Cache corrupted" #xefff0036)
    ("Request not supported" #xefff0037)
    ("Target out of resources" #xefff0038)
    ("Service did not respond" #xefff0039)
    ("ISNS server not found" #xefff003a)
    ("Operation requires reboot" #xefff003b)
    ("No portal specified" #xefff003c)
    ("Can't remove last connection" #xefff003d)
    ("Service not running" #xefff003e)
    ("Target already logged in" #xefff003f)
    ("Device busy on session" #xefff0040)
    ("Could not remove persistent login data" #xefff0042)
    ("Portal not found" #xefff0043)
    ("Initiator not found" #xefff0044)
    ("Discovery mechanism not found" #xefff0045)
    ("IPsec not supported on OS" #xefff0046)
    ("Persistent login timeout" #xefff0047)
    ("Short CHAP secret" #xafff0048) ;; #xefff0048 ??? 
    ("Evaluation period expired" #xefff0049)
    ("Invalid CHAP secret" #xefff004a)
    ("Invalid target CHAP secret" #xefff004b)
    ("Invalid initiator CHAP secret" #xefff004c)
    ("Invalid CHAP user name" #xefff004d)
    ("Invalid Logon auth type" #xefff004e)
    ("Invalid target mapping" #xefff004f)
    ("Invalid target ID" #xefff0050)
    ("Invalid iSCSI name" #xefff0051)
    ("Incompatible iSNS version" #xefff0052)
    ("Failed to configure IPsec" #xefff0053)
    ("Buffer too small" #xefff0054)
    ("Invalid load balance policy" #xefff0055)
    ("Invalid parameter" #xefff0056)
    ("Duplicate path specified" #xefff0057)
    ("Path count mismatch" #xefff0058)
    ("Invalid path ID" #xefff0059)
    ("Multiple primary paths specified" #xefff005a)
    ("No primary path specified" #xefff005b)
    ("Device already persistently bound" #xefff005c)
    ("Device not found" #xefff005d)
    ("Device not iSCSI or persistent" #xefff005e)
    ("DNS name unresolved" #xefff005f)
    ("No connection available" #xefff0060)
    ("LB policy not supported" #xefff0061)
    ("Remove connection in progress" #xefff0062)
    ("Invalid connection ID" #xefff0063)
    ("Cannot remove leading connection" #xefff0064)
    ("Restricted by group policy" #xefff0065)
    ("iSNS firewall blocked" #xefff0066)
    ("Failure to persist load balancing policy" #xefff0067)
    ("Invalid host" #xefff0068)))
     

(define-condition iscsi-error (error)
  ((code :initform 0 :initarg :code :reader iscsi-error-code))
  (:report (lambda (c stream)
             (format stream "iSCSI error 0x~X: ~A"
                     (iscsi-error-code c)
                     (or 
                      (first (find (iscsi-error-code c) *iscsi-errors*
                                   :key #'second :test #'=))
                      "Unknown")))))
  
(defun iscsi-error (code)
  (if (iscsi-error-p code)
      (error 'iscsi-error :code code)
      (get-last-error code)))

;; ------------------------------------

(defcfun (%report-iscsi-initiator-list "ReportIScsiInitiatorListW" :convention :stdcall)
    :uint32
  (count :pointer)
  (buffer :pointer))

(defun list-initiators ()
  "Returns a list of initiators." 
  (with-foreign-objects ((buffer :uint8 (* 32 1024))
                         (count :uint32))
    (setf (mem-aref count :uint32) (* 32 1024))
    (let ((res (%report-iscsi-initiator-list count buffer)))
      (cond
        ((zerop res)
         (do ((offset 0)
              (inits nil)
              (done nil))
             (done inits)
           (let ((end-offset 
                  (do ((j offset (+ j 2)))
                      ((zerop (mem-aref buffer :uint16 j)) j))))
             (cond
               ((= end-offset offset)
                (setf done t))
               (t
                (let ((str 
                       (foreign-string-to-lisp buffer
                                               :offset offset
                                               :count (- end-offset offset)
                                               :encoding :ucs-2le)))
                  (push str inits)
                  (setf offset (+ end-offset 2))))))))
        (t (iscsi-error res))))))
             
    
(defcfun (%get-initiator-node-name "GetIScsiInitiatorNodeNameW" :convention :stdcall)
    :uint32
  (name :pointer))

(defun initiator-node-name ()
  "Returns the IQN for all initiators on the system." 
  (with-foreign-object (buffer :uint8 512)
    (let ((res (%get-initiator-node-name buffer)))
      (cond
        ((zerop res)
         (nth-value 0 (foreign-string-to-lisp buffer :encoding :ucs-2le)))
        (t (iscsi-error res))))))


(defcfun (%get-session-list "GetIScsiSessionListW" :convention :stdcall)
    :uint32
  (size :pointer)
  (count :pointer)
  (buffer :pointer))

(defun maybe-foreign-string (p)
  (unless (null-pointer-p p)
    (foreign-string-to-lisp p :encoding :ucs-2le)))
  
(defcstruct uniqueid
  (unique :uint64)
  (specific :uint64))
(defstruct uniqueid
  unique specific)
(defmethod print-object ((u uniqueid) stream)
  (print-unreadable-object (u stream :type t)
    (format stream "~16,'0X-~16,'0X"
            (uniqueid-unique u) (uniqueid-specific u))))
(defun foreign-uniqueid (p)
  (make-uniqueid :unique (foreign-slot-value p '(:struct uniqueid) 'unique)
                 :specific (foreign-slot-value p '(:struct uniqueid) 'specific)))

(defcstruct conninfo
  (id (:struct uniqueid))
  (initaddr :pointer)
  (targetaddr :pointer)
  (initsocket :uint16)
  (targetsocket :uint16)
  (cid :uint16))
(defun foreign-conninfo (p)
  (list :id (foreign-uniqueid (foreign-slot-pointer p '(:struct conninfo) 'id))
        :initaddr (maybe-foreign-string (foreign-slot-value p '(:struct conninfo) 'initaddr))
        :targetaddr (maybe-foreign-string
                     (foreign-slot-value p '(:struct conninfo) 'targetaddr))
        :initsocket #+nil(let ((q (foreign-slot-pointer p '(:struct conninfo) 'initsocket)))
                      (logior (ash (mem-aref q :uint8 0) 8)
                              (ash (mem-aref q :uint8 1) 0)))
        (foreign-slot-value p '(:struct conninfo) 'initsocket)
        :targetsocket #+nil(let ((q (foreign-slot-pointer p '(:struct conninfo) 'targetsocket)))
                        (logior (ash (mem-aref q :uint8 0) 8)
                                (ash (mem-aref q :uint8 1) 0)))
        (foreign-slot-value p '(:struct conninfo) 'targetsocket)
        :cid (foreign-slot-value p '(:struct conninfo) 'cid)))

(defcstruct sessioninfo
  (id (:struct uniqueid))
  (initname :pointer)
  (nodename :pointer)
  (targetname :pointer)
  (isid :uint8 :count 6)
  (tsid :uint16)
  (ccount :uint32)
  (connections :pointer))
(defun foreign-sessioninfo (p)
  (list :id (foreign-uniqueid (foreign-slot-pointer p '(:struct sessioninfo) 'id))
        :initiator-name (maybe-foreign-string
                         (foreign-slot-value p '(:struct sessioninfo) 'initname))
        :target-node-name (maybe-foreign-string
                           (foreign-slot-value p '(:struct sessioninfo) 'nodename))
        :target-name (maybe-foreign-string
                      (foreign-slot-value p '(:struct sessioninfo) 'targetname))
        :isid (let ((a (make-array 6))
                    (q (foreign-slot-pointer p '(:struct sessioninfo) 'isid)))
                (dotimes (j 6)
                  (setf (aref a j) (mem-aref q :uint8 j)))
                a)
        :tsid (foreign-slot-value p '(:struct sessioninfo) 'tsid)
        :connections
        (do ((j 0 (1+ j))
             (conns nil))
            ((= j (foreign-slot-value p '(:struct sessioninfo) 'ccount))
             conns)
          (let ((q (mem-aptr (foreign-slot-value p '(:struct sessioninfo) 'connections) '(:struct conninfo) j)))
            (push (foreign-conninfo q) conns)))))
  


(defun list-sessions ()
  "Returns a list of all sessions." 
  (with-foreign-objects ((count :uint32)
                         (size :uint32)
                         (buffer :uint8 (* 32 1024)))
    (setf (mem-aref size :uint32) (* 32 1024))
    (let ((res (%get-session-list size count buffer)))
      (unless (zerop res) (iscsi-error res))

      (do ((i 0 (1+ i))
           (sessions nil))
          ((= i (mem-aref count :uint32)) sessions)
        (let ((p (mem-aptr buffer '(:struct sessioninfo) i)))
          (push (foreign-sessioninfo p) sessions))))))

(defcstruct loginoptions
  (version :uint32)
  (infospec :uint32)
  (flags :uint32)
  (authtypes :uint32)
  (headerdigest :uint32)
  (datadigest :uint32)
  (maxconnections :uint32)
  (time2wait :uint32)
  (time2retain :uint32)
  (userlen :uint32)
  (passlen :uint32)
  (user :pointer)
  (pass :pointer))

(defun foreign-loginoptions (p)
  (flet ((slot (name)
           (foreign-slot-value p '(:struct loginoptions) name)))
    (list :version (slot 'version)
          :specified (slot 'infospec)
          :flags (slot 'flags)
          :authtypes (slot 'authtypes)
          :headerdigest (slot 'headerdigest)
          :datadigest (slot 'datadigest)
          :maxconnections (slot 'maxconnections)
          :time2wait (slot 'time2wait)
          :time2retain (slot 'time2retain)
          :user (let ((count (slot 'userlen)))
                  (unless (zerop count)
                    (foreign-string-to-lisp (slot 'user)
                                            :count (* count 2))))
          :pass (let ((count (slot 'passlen)))
                  (unless (zerop count)
                    (foreign-string-to-lisp (slot 'pass)
                                            :count (* count 2)))))))

(defun memset (p type &optional (value 0))
  (dotimes (i (foreign-type-size type))
    (setf (mem-aref p :uint8 i) value))
  p)

(defun loginoptions-foreign (p &key flags authtype headerdigest datadigest time2wait time2retain user pass maxconnections)
  (memset p '(:struct loginoptions))
  (with-foreign-string ((ustr ulen) (or user "") :encoding :utf-8)
    (with-foreign-string ((pstr plen) (or pass "") :encoding :utf-8)
      (let ((specified 0))
        (mapc (lambda (field value f)
                (when value 
                  (setf (foreign-slot-value p '(:struct loginoptions) field)
                        value
                        specified (logior specified f))))
              '(version flags authtype headerdigest datadigest time2wait time2retain
                userlen passlen user pass maxconnections)
              (list 1 flags authtype headerdigest datadigest time2wait time2retain
                    (when user ulen) (when user ustr)
                    (when pass plen) (when pass pstr)
                    maxconnections)
              '(0 0 #x80 #x1 #x2 #x8 #x10 0 0 #x20 #x40 #x4))
        (setf (foreign-slot-value p '(:struct loginoptions) 'infospec)
              specified)
        p))))
  
(defcstruct targetportal
  (name :uint16 :count 256)
  (address :uint16 :count 256)
  (socket :uint16))
(defun targetportal-foreign (p &key name address socket)
  (memset p '(:struct targetportal))
  (when name
    (lisp-string-to-foreign name
                            (foreign-slot-pointer p '(:struct targetportal) 'name)
                            512
                            :encoding :ucs-2le))
  (when address
    (lisp-string-to-foreign address
                            (foreign-slot-pointer p '(:struct targetportal) 'address)
                            512
                            :encoding :ucs-2le))
  (when socket
    (setf (foreign-slot-value p '(:struct targetportal) 'socket)
          socket))
  p)
  
  
(defcfun (%add-send-target-portal "AddIScsiSendTargetPortalW" :convention :stdcall)
    :uint32
  (initname :pointer)
  (port :uint32)
  (options :pointer)
  (security-flags :uint32)
  (portal :pointer))

(defun add-send-target-portal (portal-address
                               &key portal-socket portal-name
                                 initiator-name initiator-port
                                 flags authtype headerdigest datadigest
                                 time2wait time2retain user pass)
  "Add a portal to use with sendtargets discovery.
PORTAL-ADDRESS ::= IP or hostname.
PORTAL-SOCKET ::= port defaults to 3260.
" 
  (with-foreign-objects ((iso '(:struct loginoptions))
                         (isp '(:struct targetportal)))
    (with-foreign-string (istr (or initiator-name "") :encoding :ucs-2le)
      (loginoptions-foreign iso
                            :flags flags :authtype authtype
                            :headerdigest headerdigest
                            :datadigest datadigest
                            :time2wait time2wait
                            :time2retain time2retain
                            :user user :pass pass)
      (targetportal-foreign isp
                            :name portal-name
                            :address portal-address
                            :socket (or portal-socket 3260))
      (let ((res (%add-send-target-portal (if initiator-name istr (null-pointer))
                                          (or initiator-port #xffffffff)
                                          iso
                                          0
                                          isp)))
        (unless (zerop res) (iscsi-error res))

        nil))))

(defcfun (%remove-send-target-portal "RemoveIScsiSendTargetPortalW" :convention :stdcall)
    :uint32
  (initiator :pointer)
  (port :uint32)
  (portal :pointer))

(defun remove-send-target-portal (portal-address &key portal-socket portal-name initiator-instance initiator-port)
  "Remove a portal.
ADDRESS ::= IP or hostname for the portal.
SOCKET ::= port number defaults to 3260.
" 
  (with-foreign-object (isp '(:struct targetportal))
    (with-foreign-string (istr (or initiator-instance "") :encoding :ucs-2le)
      (targetportal-foreign isp
                            :name portal-name
                            :address portal-address
                            :socket (or portal-socket 3260))
      (let ((res (%remove-send-target-portal (if initiator-instance istr (null-pointer))
                                             (or initiator-port #xffffffff)
                                             isp)))
        (unless (zerop res)
          (iscsi-error res))
        nil))))

(defcfun (%login-target "LoginIScsiTargetW" :convention :stdcall)
    :uint32
  (targetname :pointer)
  (informational-session :boolean)
  (initiator-name :pointer)
  (initiator-port :uint32)
  (portal :pointer)
  (security-flags :uint32)
  (mappings :pointer)
  (options :pointer)
  (keysize :uint32)
  (key :pointer)
  (persistent :boolean)
  (sid :pointer)
  (cid :pointer))

(defun login-target (target-name
                     &key informational-session-p initiator-name
                       initiator-port portal-name portal-address portal-socket
                       flags authtype headerdigest datadigest
                       time2wait time2retain user pass                       
                       persistentp)
  "Login a new session to an iSCSI target. The target must already have been discovered." 
  (with-foreign-objects ((iso '(:struct loginoptions))
                         (sid '(:struct uniqueid))
                         (cid '(:struct uniqueid))
                         (isp '(:struct targetportal)))
    (with-foreign-strings ((tstr target-name :encoding :ucs-2le)
                           (istr (or initiator-name "") :encoding :ucs-2le))
      (loginoptions-foreign iso
                            :flags flags :authtype authtype
                            :headerdigest headerdigest
                            :datadigest datadigest
                            :time2wait time2wait
                            :time2retain time2retain
                            :user user :pass pass)
      (targetportal-foreign isp :name portal-name
                            :address portal-address
                            :socket (or portal-socket 3260))
      (let ((res (%login-target tstr
                                informational-session-p
                                (if initiator-name istr (null-pointer))
                                (or initiator-port #xffffffff)
                                (if portal-address isp (null-pointer))
                                0 
                                (null-pointer)
                                iso
                                0
                                (null-pointer)
                                persistentp
                                sid
                                cid)))
        (unless (zerop res) (iscsi-error res))
        (values (foreign-uniqueid sid)
                (foreign-uniqueid cid))))))
                                

(defcfun (%report-targets "ReportIScsiTargetsW" :convention :stdcall)
    :uint32
  (force-update :boolean)
  (size :pointer)
  (buffer :pointer))

(defun list-targets (&optional force-update-p)
  "Returns a list of IQNs for all discovered iSCSI targets." 
  (with-foreign-objects ((size :uint32)
                         (buffer :uint8 (* 32 1024)))
    (setf (mem-aref size :uint32) (* 32 1024))
    (let ((res (%report-targets force-update-p
                                size
                                buffer)))
      (unless (zerop res) (iscsi-error res))

      (do ((targets nil)
           (offset 0)
           (done nil))
          (done targets)
        (multiple-value-bind (str count) (foreign-string-to-lisp buffer
                                                                 :offset offset
                                                                 :encoding :ucs-2le)
          (cond
            ((string= str "")
             (setf done t))
            (t 
             (push str targets)
             (incf offset count))))))))

(defcfun (%logout-target "LogoutIScsiTarget" :convention :stdcall)
    :uint32
  (sid :pointer))

(defun logout-target (sid)
  "Logout an iSCSI session.
SID ::= session ID as returned from LOGIN-TARGET or LIST-SESSIONS.
"
  (declare (type uniqueid sid))
  (with-foreign-object (s '(:struct uniqueid))
    (setf (foreign-slot-value s '(:struct uniqueid) 'specific)
          (uniqueid-specific sid)
          (foreign-slot-value s '(:struct uniqueid) 'unique)
          (uniqueid-unique sid))
    (let ((res (%logout-target s)))
        (if (zerop res)
            (iscsi-error res)
            nil))))

(defcfun (%refresh-send-target-portal "RefreshIScsiSendTargetPortalW" :convention :stdcall)
    :uint32
  (initiator-instance :pointer)
  (initiator-port :uint32)
  (portal :pointer))

(defun refresh-send-target-portal (portal-address &key portal-socket portal-name initiator-instance initiator-port)
  "Perform an iSCSI sendtargets discovery on the portal." 
  (with-foreign-object (isp '(:struct targetportal))
    (with-foreign-string (istr (or initiator-instance "") :encoding :ucs-2le)
      (targetportal-foreign isp
                            :name portal-name
                            :address portal-address
                            :socket (or portal-socket 3260))
      (let ((res (%refresh-send-target-portal (if initiator-instance istr (null-pointer))
                                              (or initiator-port #xffffffff)
                                              isp)))
        (if (zerop res)
            (iscsi-error res)
            nil)))))


(defcfun (%report-send-target-portals "ReportIScsiSendTargetPortalsExW" :convention :stdcall)
    :uint32
  (count :pointer)
  (size :pointer)
  (buffer :pointer))

(defcstruct portalinfoex
  (initiator-name :uint16 :count 256)
  (initiator-port :uint32)
  (portal-name :uint16 :count 256)
  (portal-address :uint16 :count 256)
  (portal-socket :uint16)
  (security-flags :uint32)
  (login-options (:struct loginoptions)))

(defun foreign-portalinfoex (p)
  (list :initiator-name (foreign-string-to-lisp (foreign-slot-pointer p '(:struct portalinfoex) 'initiator-name)
                                                :encoding :ucs-2le)
        :initiator-port (foreign-slot-value p '(:struct portalinfoex) 'initiator-port)
        :portal-name (foreign-string-to-lisp (foreign-slot-pointer p '(:struct portalinfoex) 'portal-name)
                                             :encoding :ucs-2le)
        :portal-address (foreign-string-to-lisp (foreign-slot-pointer p '(:struct portalinfoex) 'portal-address)
                                                :encoding :ucs-2le)
        :portal-socket (foreign-slot-value p '(:struct portalinfoex) 'portal-socket)
        :security-flags (foreign-slot-value p '(:struct portalinfoex) 'security-flags)
        :login-options (foreign-loginoptions
                        (foreign-slot-pointer p '(:struct portalinfoex) 'login-options))))

                                                
(defun list-send-target-portals ()
  "List all portals to use for sendtarget discovery." 
  (with-foreign-objects ((count :uint32)
                         (size :uint32)
                         (buffer :uint8 (* 32 1024)))
    (setf (mem-aref size :uint32) (* 32 1024))
    (let ((res (%report-send-target-portals count size buffer)))
      (unless (zerop res) (iscsi-error res))

      (do ((i 0 (1+ i))
           (portals nil))
          ((= i (mem-aref count :uint32)) portals)
        (let ((p (mem-aptr buffer '(:struct portalinfoex) i)))
          (push (foreign-portalinfoex p) portals))))))
