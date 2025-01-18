const express = require('express');
const router = express.Router();
const fetchUser = require('../middleware/fetchUser');
const { body, validationResult } = require('express-validator');
const Note = require('../models/Notes');

// ROUTE 1: Get all the notes Using GET "/api/notes/fetchallnotes". login required
router.get('/fetchallnotes', fetchUser, async (req, res) => {
    try {
        const notes = await Note.find({ user: req.user.id });
        res.json(notes);
    } catch (error) {
        console.error(error.message);
        res.status(500).send("Internal Server Error");
    }
});

// ROUTE 2: Add a new note Using POST "/api/notes/addnote". login required
router.post('/addnote', fetchUser, [
    body('title', 'Enter a valid title').isLength({ min: 3 }),
    body('description', 'Description must be at least 5 characters').isLength({ min: 5 }),
], async (req, res) => {
    const { title, description, tag } = req.body;

    // If there are errors, return bad request and the errors
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }

    try {
        const note = new Note({
            title, description, tag, user: req.user.id
        });

        const saveNote = await note.save();
        res.json(saveNote);
    } catch (error) {
        console.error(error.message);
        res.status(500).send("Internal Server Error");
    }
});

// ROUTE 3: Update an existing note Using PUT "/api/notes/updatenote/:id". login required
router.put('/updatenote/:id', fetchUser, async (req, res) => {
    const { title, description, tag } = req.body;
    
    // Create a newNote object to update
    const newNote = {};
    if (title) newNote.title = title;
    if (description) newNote.description = description;
    if (tag) newNote.tag = tag;

    try {
        // Find the note by ID
        let note = await Note.findById(req.params.id);

        // If note not found, return 404
        if (!note) {
            return res.status(404).send("Not Found");
        }

        // Check if the user owns the note
        if (note.user.toString() !== req.user.id) {
            return res.status(401).send("Not Allowed");
        }

        // Update the note
        note = await Note.findByIdAndUpdate(
            req.params.id,
            { $set: newNote },
            { new: true }
        );

        res.json({ note });
    } catch (error) {
        console.error(error.message);
        res.status(500).send("Internal Server Error");
    }
});

// ROUTE 4: delete an existing note Using DELETE "/api/notes/deletenote/:id". login required
router.delete('/deletenote/:id', fetchUser, async (req, res) => {
    try {
        // Find the note to be deleted
        const note = await Note.findById(req.params.id);

        // If note not found, return 404
        if (!note) {
            return res.status(404).send("Note not found");
        }

        // Check if the user owns the note
        if (note.user.toString() !== req.user.id) {
            return res.status(401).send("Not Allowed");
        }

        // Delete the note
        await Note.findByIdAndDelete(req.params.id);

        res.json({ success: "Note has been deleted",note:note });
    } catch (error) {
        console.error(error.message);
        res.status(500).send("Internal Server Error");
    }
});

module.exports = router;
