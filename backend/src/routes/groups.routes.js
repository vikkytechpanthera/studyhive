const router = require('express').Router();
const { body } = require('express-validator');
const ctrl  = require('../controllers/groups.controller');
const { requireAuth, requireGroupRole } = require('../middleware/auth');

const groupRules = [
  body('name').trim().notEmpty().withMessage('Group name required.'),
  body('maxMembers').optional().isInt({ min:2, max:100 }),
];

// All group routes require auth
router.use(requireAuth);

router.get ('/',              ctrl.listMyGroups);
router.post('/',  groupRules, ctrl.createGroup);
router.post('/join',          ctrl.joinByInvite);

router.get   ('/:groupId', requireGroupRole('member'), ctrl.getGroup);
router.patch ('/:groupId', requireGroupRole('owner'),  ctrl.updateGroup);
router.delete('/:groupId', requireGroupRole('owner'),  ctrl.deleteGroup);

router.get   ('/:groupId/members',              requireGroupRole('member'),    ctrl.listMembers);
router.delete('/:groupId/leave',                requireGroupRole('member'),    ctrl.leaveGroup);
router.patch ('/:groupId/members/:userId/role', requireGroupRole('moderator'), ctrl.updateMemberRole);

module.exports = router;
